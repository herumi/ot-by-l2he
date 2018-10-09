#include "util.hpp"

int main()
	try
{
	using namespace mcl::she;
	initOT();
	using namespace picojson;
	value v;
	std::cin >> v;
	CipherTextGT ct;
	JsonToCipherTextGT(ct, v);

	const char *secStr = "673406c280f5475db8f7b9dec0fc662bedb4e6a536ef8d628e71e898b632911ba90e0ffe43fe224263f690b61692dca96b941846b375e58046f01974782fc509";
	SecretKey sec;
	sec.setStr(secStr, mcl::IoSerializeHexStr);
	printf("%d\n", (int)sec.dec(ct));
} catch (std::exception& e) {
	printf("err %s\n", e.what());
	return 1;
}
