#pragma once
#include <stdio.h>
#include <string.h>
#include <string>
#include <map>
#include <vector>
#include <iostream>
#include <omp.h>
#include <cybozu/socket.hpp>
#include <cybozu/option.hpp>
#include <mcl/she.hpp>
#include "picojson.h"

using namespace mcl::she;
typedef std::vector<std::string> StrVec;
typedef std::vector<CipherTextG1> C1Vec;
typedef std::vector<CipherTextG2> C2Vec;

/*
	{ "ret":"<gt>" }
*/
inline void CipherTextGTtoJson(picojson::value& v, const CipherTextGT& ct)
{
	using namespace picojson;
	v.set<object>(object());
	object& o = v.get<object>();
	o["ret"] = value(ct.getStr(mcl::IoSerializeHexStr));
}

inline void JsonToCipherTextGT(CipherTextGT& ct, const picojson::value& v)
{
	using namespace picojson;
	const object& o = v.get<object>();
	object::const_iterator i = o.find("ret");
	if (i == o.end()) throw cybozu::Exception("JsonToCipherTextGT:ret is not found");
	ct.setStr(i->second.get<std::string>(), mcl::IoSerializeHexStr);
}

inline void initOT()
{
	mcl::she::init(mcl::BN254);
	G1::setOrder(0);
	G2::setOrder(0);
}

/*
	{
		"ret":[
			["<num>", "<c1>", ...],
			["<num>", "<c2>", ...]
		]
	}
*/
struct OT {
	C1Vec c1v;
	C2Vec c2v;
	template<class V>
	void setVec(V& v, const picojson::array& a) const
	{
		if (a.empty()) throw cybozu::Exception("setVec:empty");
		size_t n = cybozu::atoi(a[0].get<std::string>());
		if (n + 1 != a.size()) throw cybozu::Exception("setVec:bad size") << n << a.size();
		v.resize(n);
		for (size_t i = 0; i < n; i++) {
			v[i].setStr(a[i + 1].get<std::string>(), mcl::IoSerializeHexStr);
		}
	}
	template<class V>
	void getVec(picojson::array&a, const V& v) const
	{
		using namespace picojson;
		const size_t n = v.size();
		a.resize(n + 1);
		a[0] = value(cybozu::itoa(v.size()));
		for (size_t i = 0; i < n; i++) {
			a[i + 1] = value(v[i].getStr(mcl::IoSerializeHexStr));
		}
	}
	void set(const picojson::value& v)
	{
		using namespace picojson;
		const object& o = v.get<object>();
		object::const_iterator i = o.find("ret");
		if (i == o.end()) throw cybozu::Exception("OT::set:ret is not found");
		const array& a = i->second.get<array>();
		if (a.size() != 2) throw cybozu::Exception("OT::set:bad size") << a.size();
		setVec(c1v, a[0].get<array>());
		setVec(c2v, a[1].get<array>());
	}
	void get(picojson::value& v) const
	{
		using namespace picojson;
		v.set<object>(object());
		object& o = v.get<object>();
		array a;
		a.resize(2);
		a[0].set<array>(array());
		a[1].set<array>(array());
		getVec(a[0].get<array>(), c1v);
		getVec(a[1].get<array>(), c2v);
		o["ret"].set<array>(a);
	}
	void dumpDec(const SecretKey& sec) const
	{
		fprintf(stderr, "c1v=");
		for (size_t i = 0; i < c1v.size(); i++) {
			fprintf(stderr, "%d, ", (int)sec.dec(c1v[i]));
		}
		fprintf(stderr, "\n");

		fprintf(stderr, "c2v=");
		for (size_t i = 0; i < c2v.size(); i++) {
			fprintf(stderr, "%d, ", (int)sec.dec(c2v[i]));
		}
		fprintf(stderr, "\n");
	}
	template<class Vec>
	void innerproduct(CipherTextG1& out, const C1Vec& cv, const Vec *v, size_t vn) const
	{
		assert(!cv.empty() && vn > 0);
		out = cv[0];
		CipherTextG1::mul(out, out, v[0]);
		CipherTextG1 t;
		const size_t n = std::min(cv.size(), vn);
		for (size_t i = 1; i < n; i++) {
			CipherTextG1::mul(t, cv[i], v[i]);
			CipherTextG1::add(out, out, t);
		}
	}
	/*
		c1vTbl[i * maxFactor + j] = c1v[i] * j
	*/
	void precomputeSmallFactorCipherTextG1(C1Vec& c1vTbl, const C1Vec& c1v, int maxFactor) const
	{
		assert(maxFactor > 2);
		c1vTbl.resize(c1v.size() * maxFactor);
		CipherTextG1 *p = c1vTbl.data();
		for (size_t i = 0; i < c1v.size(); i++) {
			CipherTextG1::mul(p[0], c1v[i], 0);
			for (int j = 1; j < maxFactor; j++) {
				CipherTextG1::add(p[j], p[j - 1], c1v[i]);
			}
			p += maxFactor;
		}
	}
	template<class Vec>
	void innerproductPrecomputed(CipherTextG1& out, const C1Vec& c1vTbl, int maxFactor, const Vec *v, size_t n) const
	{
		assert(!c1vTbl.empty() && n > 0);
		out = c1vTbl[v[0]];
		for (size_t i = 1; i < n; i++) {
			assert(0 <= v[i] && v[i] < maxFactor);
			if (v[i]) {
				CipherTextG1::add(out, out, c1vTbl[i * maxFactor + v[i]]);
			}
		}
	}
	template<class Vec>
	void calc(CipherTextGT& ct, const Vec* v, size_t vn) const
	{
		if (c1v.empty() || c2v.empty() || vn == 0 || vn < c1v.size()) {
			throw cybozu::Exception("too short vn") << c1v.size() << vn;
		}
		C1Vec c1vTbl;
		const int maxFactor = 10;
		precomputeSmallFactorCipherTextG1(c1vTbl, c1v, maxFactor);
		const size_t M = c1v.size();
		const size_t N = std::min((vn + M - 1) / M, c2v.size());
		std::vector<CipherTextGT> ctv(N);

#pragma omp parallel for
		for (size_t i = 0; i < N - 1; i++) {
			CipherTextG1 c1;
			innerproductPrecomputed(c1, c1vTbl, maxFactor, &v[i * M], M);
			CipherTextGT::mulML(ctv[i], c1, c2v[i]);
		}
		const size_t remain = std::min(vn - (N - 1) * M, M);
		{
			size_t i = N - 1;
			CipherTextG1 c1;
			innerproductPrecomputed(c1, c1vTbl, maxFactor, &v[i * M], remain);
			CipherTextGT::mulML(ctv[i], c1, c2v[i]);
		}

		ct = ctv[0];
		for (size_t i = 1; i < ctv.size(); i++) {
			CipherTextGT::add(ct, ct, ctv[i]);
		}
		CipherTextGT::finalExp(ct, ct);
	}
};
