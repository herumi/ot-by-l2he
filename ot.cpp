#include "util.hpp"
#include <time.h>
#include <cybozu/mmap.hpp>

template<class OutputStream>
void SendResponse(OutputStream& os, const std::string& in, const std::string& contentType)
{
	std::ostringstream oss;
	oss << "HTTP/1.0 200 OK\r\n"
	   << "Content-Length: " << in.size() << "\r\n"
	   << "Connection: close\r\n"
	   << "Access-Control-Allow-Origin: *\r\n"
	   << "X-Content-Type-Options: nosniff\r\n"
	   << "Content-Type: " << contentType << "\r\n";
	oss << "\r\n";
	const std::string& header = oss.str();
	os.write(header.c_str(), header.size());
	os.write(in.c_str(), in.size());
}

const char *g_pi =
"31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679"
"82148086513282306647093844609550582231725359408128481117450284102701938521105559644622948954930381964"
"42881097566593344612847564823378678316527120190914564856692346034861045432664821339360726024914127372"
"45870066063155881748815209209628292540917153643678925903600113305305488204665213841469519415116094330"
"57270365759591953092186117381932611793105118548074462379962749567351885752724891227938183011949129833"
"67336244065664308602139494639522473719070217986094370277053921717629317675238467481846766940513200056"
"81271452635608277857713427577896091736371787214684409012249534301465495853710507922796892589235420199"
"56112129021960864034418159813629774771309960518707211349999998372978049951059731732816096318595024459"
"45534690830264252230825334468503526193118817101000313783875288658753320838142061717766914730359825349"
"04287554687311595628638823537875937519577818577805321712268066130019278766111959092164201989";

int main(int argc, char *argv[])
	try
{
	cybozu::Option opt;
	bool doTest;
	opt.appendBoolOpt(&doTest, "t", "test");
	opt.appendHelp("h", "show this message");
	if (!opt.parse(argc, argv)) {
		opt.usage();
		return 1;
	}
	const char *secStr = "673406c280f5475db8f7b9dec0fc662bedb4e6a536ef8d628e71e898b632911ba90e0ffe43fe224263f690b61692dca96b941846b375e58046f01974782fc509";
	cybozu::Mmap piMap("./pi1m.txt");
	const char *pi = piMap.get();
	const size_t piN = piMap.size();
	initOT();
	SecretKey sec;
	sec.setStr(secStr, mcl::IoSerializeHexStr);
//	sec.setByCSPRNG();
	PublicKey pub;
	sec.getPublicKey(pub);

	OT ot;
	picojson::value v;
	std::cin >> v;
	std::string err;
	if (std::cin.fail()) {
		fprintf(stderr, "err %s\n", err.c_str());
		return 1;
	}
	ot.set(v);
	CipherTextGT ct;
	std::vector<uint8_t> tbl;
	tbl.resize(piN);
	for (size_t i = 0; i < tbl.size(); i++) {
		tbl[i] = uint8_t(pi[i] - '0');
	}
//	ot.calc(ct, g_pi, strlen(g_pi));
	ot.calc(ct, tbl.data(), tbl.size());
	CipherTextGTtoJson(v, ct);
	std::string str = v.serialize();
	if (doTest) {
		printf("%s\n", str.c_str());
	} else {
		const char *contentType = "application/javascript";
		SendResponse(std::cout, str, contentType);
	}

} catch (std::exception& e) {
	printf("ERR %s\n", e.what());
	return 1;
}
