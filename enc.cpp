#include "util.hpp"

int main(int argc, char *argv[])
	try
{
	cybozu::Option opt;
	int n;
	int m;
	int pos;
	opt.appendOpt(&n, 10, "n");
	opt.appendOpt(&m, 10, "m");
	opt.appendParam(&pos, "pos");
	opt.appendHelp("h", "show this message");
	if (!opt.parse(argc, argv)) {
		opt.usage();
		return 1;
	}
	if (n <= 0 || m <= 0 || pos < 0 || pos >= n * m) {
		fprintf(stderr, "bad (n, m, pos) = (%d, %d, %d)\n", n, m, pos);
		return 1;
	}
	fprintf(stderr, "n=%d, m=%d, pos=%d\n", n, m, pos);
	const char *secStr = "673406c280f5475db8f7b9dec0fc662bedb4e6a536ef8d628e71e898b632911ba90e0ffe43fe224263f690b61692dca96b941846b375e58046f01974782fc509";
	initOT();
	SecretKey sec;
	sec.setStr(secStr, mcl::IoSerializeHexStr);
//	sec.setByCSPRNG();
//	sec.setStr("123 456");
	PublicKey pub;
	sec.getPublicKey(pub);

	int q, r;
	q = pos / n; // 0 <= q < m
	r = pos % n; // 0 <= r < n
	OT ot;
	ot.c1v.resize(n);
	ot.c2v.resize(m);
	for (int i = 0; i < n; i++) {
		pub.enc(ot.c1v[i], i == r ? 1 : 0);
	}
	for (int i = 0; i < m; i++) {
		pub.enc(ot.c2v[i], i == q ? 1 : 0);
	}
	picojson::value v;
	ot.get(v);
	printf("%s", v.serialize().c_str());
} catch (std::exception& e) {
	printf("err %s\n", e.what());
	return 1;
}
