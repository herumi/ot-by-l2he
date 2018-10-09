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
