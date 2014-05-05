/**************************************************************************************

Copyright © 2004-2014 GoPivotal, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,  WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.

Written by Mark Venguerov 2013-2014

**************************************************************************************/

#ifdef _MSC_VER
#ifndef _WIN32_WINNT                
#define _WIN32_WINNT _WIN32_WINNT_VISTA
#endif						
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#define _strnicmp strncasecmp
#endif

#include <startup.h>
#include <afyutils.h>
#include <afysock.h>
#include <string.h>
#include <stdio.h>
#include <new>

using namespace Afy;

namespace AfyHttp
{

#define	HTTP_SERVICE_NAME		AFFINITY_SERVICE_PREFIX "HTTP"
#define	HTTP_PROP_NAME			AFFINITY_SERVICE_PREFIX "HTTP"

#define	HTTP_DEFAULT_HEADER		0x1000
#define	HTTP_DEFAULT_TRAILER	0x0010

	enum HttpPropNames
{
	HTTP_METHOD, HTTP_URL, HTTP_CODE, HTTP_REASON, HTTP_REQUEST_FIELDS, HTTP_RESPONSE_FIELDS, HTTP_FNAME, HTTP_FVALUE, HTTP_URL_SCHEME,
	HTTP_URL_USERNAME, HTTP_URL_PASSWORD, HTTP_URL_HOST, HTTP_URL_PORT, HTTP_URL_PATH, HTTP_URL_QUERY, HTTP_URL_QUERY_PARTS, HTTP_URL_FRAGMENT,
	HTTP_HTTP_FIELDS, HTTP_TRANSFER_ENCODING=HTTP_HTTP_FIELDS, HTTP_CONNECTION, HTTP_DATE, HTTP_ACCEPT, HTTP_HOST, HTTP_USER_AGENT
};

const static char *propURIs[] =
{
	HTTP_PROP_NAME "/method",
	HTTP_PROP_NAME "/url",
	HTTP_PROP_NAME "/code",
	HTTP_PROP_NAME "/reason",
	HTTP_PROP_NAME "/request/fields",
	HTTP_PROP_NAME "/response/fields",
	HTTP_PROP_NAME "/fieldName",
	HTTP_PROP_NAME "/fieldValue",
	HTTP_PROP_NAME "/url/scheme",
	HTTP_PROP_NAME "/url/username",
	HTTP_PROP_NAME "/url/password",
	HTTP_PROP_NAME "/url/host",
	HTTP_PROP_NAME "/url/port",
	HTTP_PROP_NAME "/url/path",
	HTTP_PROP_NAME "/url/query",
	HTTP_PROP_NAME "/url/queryParts",
	HTTP_PROP_NAME "/url/fragment",
};

// RFC 2616 methods

enum HttpMethods
{
	HM_OPTIONS, HM_GET, HM_HEAD, HM_POST, HM_PUT, HM_DELETE, HM_TRACE, HM_CONNECT
};

const static KWInit strMethods[] =
{
	{"OPTIONS",		HM_OPTIONS},
	{"GET",			HM_GET},
	{"HEAD",		HM_HEAD},
	{"POST",		HM_POST},
	{"PUT",			HM_PUT},
	{"DELETE",		HM_DELETE},
	{"TRACE",		HM_TRACE},
	{"CONNECT",		HM_CONNECT},
};

// RFC 2616 headers

const static KWInit strGeneralHeaders[] =
{
	{"Cache-Control",		~0u},
	{"Connection",			HTTP_CONNECTION},
	{"Date",				HTTP_DATE},
	{"Pragma",				~0u},
	{"Trailer",				~0u},
	{"Transfer-Encoding",	HTTP_TRANSFER_ENCODING},
	{"Upgrade",				~0u},
	{"Via",					~0u},
	{"Warning",				~0u},
};

const static KWInit strRequestHeaders[] =
{
	{"Accept",				HTTP_ACCEPT},
	{"Accept-Charset",		~0u},
	{"Accept-Encoding",		~0u},
	{"Accept-Language",		~0u},
	{"Authorization",		~0u},
	{"Expect",				~0u},
	{"From",				~0u},
	{"Host",				HTTP_HOST},
	{"If-Match",			~0u},
	{"If-Modified-Since",	~0u},
	{"If-None-Match",		~0u},
	{"If-Range",			~0u},
	{"If-Unmodified-Since",	~0u},
	{"Max-Forwards",		~0u},
	{"Proxy-Authorization",	~0u},
	{"Range",				~0u},
	{"Referer",				~0u},
	{"TE",					~0u},
	{"User-Agent",			HTTP_USER_AGENT},
};

const static KWInit strResponseHeaders[] =
{
	{"Accept-Ranges",		~0u},
	{"Age",					~0u},
	{"ETag",				~0u},
	{"Location",			~0u},
	{"Proxy-Authenticate",	~0u},
	{"Retry-After",			~0u},
	{"Server",				~0u},
	{"Vary",				~0u},
	{"WWW-Authenticate",	~0u},
};

const static KWInit strEntityHeaders[] =
{
	{"Allow",				~0u},
	{"Content-Encoding",	~0u},
	{"Content-Language",	~0u},
	{"Content-Length",		PROP_SPEC_CONTENTLENGTH|0x80000000},
	{"Content-Location",	~0u},
	{"Content-MD5",			~0u},
	{"Content-Range",		~0u},
	{"Content-Type",		PROP_SPEC_CONTENTTYPE|0x80000000},
	{"Expires",				~0u},
	{"Last-Modified",		~0u},
};

#define	HTTP_CODE_OK	200
#define	HTTP_REASON_OK	"OK"

const static struct ResponseCode {
	unsigned	code;
	const char	*reason;
} strResponses[] =
{
	{100,	"Continue"},
	{101,	"Switching Protocols"},
	{200,	"OK"},
	{201,	"Created"},
	{202,	"Accepted"},
	{203,	"Non-Authoritative Information"},
	{204,	"No Content"},
	{205,	"Reset Content"},
	{206,	"Partial Content"},
	{300,	"Multiple Choices"},
	{301,	"Moved Permanently"},
	{302,	"Found"},
	{303,	"See Other"},
	{304,	"Not Modified"},
	{305,	"Use Proxy"},
	{307,	"Temporary Redirect"},
	{400,	"Bad Request"},
	{401,	"Unauthorized"},
	{402,	"Payment Required"},
	{403,	"Forbidden"},
	{404,	"Not Found"},
	{405,	"Method Not Allowed"},
	{406,	"Not Acceptable"},
	{407,	"Proxy Authentication Required"},
	{408,	"Request Time-out"},
	{409,	"Conflict"},
	{410,	"Gone"},
	{411,	"Length Required"},
	{412,	"Precondition Failed"},
	{413,	"Request Entity Too Large"},
	{414,	"Request-URI Too Large"},
	{415,	"Unsupported Media Type"},
	{416,	"Requested range not satisfiable"},
	{417,	"Expectation Failed"},
	{500,	"Internal Server Error"},
	{501,	"Not Implemented"},
	{502,	"Bad Gateway"},
	{503,	"Service Unavailable"},
	{504,	"Gateway Time-out"},
	{505,	"HTTP Version not supported"}
};

#define	HTTP_PROTOCOL	"http://"
#define	HTTPS_PROTOCOL	"https://"
#define	HTTP_VERSION	"HTTP/1.1"
#define	HTTP_CHUNKED	"chunked"
#define	HTTP_KEEPALIVE	"Keep-Alive"
#define	HTTP_TRENC		"Transfer-Encoding"
#define	HTTP_CONTTYPE	"Content-Type"
#define	HTTP_CONTLEN	"Content-Length"
#define	HTTP_ENDCHUNK	"0\r\n\r\n"

KWTrie	*methods = NULL;
KWTrie	*rqHeaders = NULL;
KWTrie	*rsHeaders = NULL;

enum HTTPCharType
{
	_OC, _CT, _TA, _LF, _CR, _SP, _DQ, _SE, _TO, _DI, _UP, _LO
};

const HTTPCharType charType[256] = 
{
	_CT,_CT,_CT,_CT,_CT,_CT,_CT,_CT,_CT,_TA,_LF,_CT,_CT,_CR,_CT,_CT,							// 0x00 - 0x0F
	_CT,_CT,_CT,_CT,_CT,_CT,_CT,_CT,_CT,_CT,_CT,_CT,_CT,_CT,_CT,_CT,							// 0x10 - 0x1F
	_SP,_TO,_DQ,_TO,_TO,_TO,_TO,_TO,_SE,_SE,_TO,_TO,_SE,_TO,_TO,_SE,							// 0x20 = 0x2F
	_DI,_DI,_DI,_DI,_DI,_DI,_DI,_DI,_DI,_DI,_SE,_SE,_SE,_SE,_SE,_SE,							// 0x30 - 0x3F
	_SE,_UP,_UP,_UP,_UP,_UP,_UP,_UP,_UP,_UP,_UP,_UP,_UP,_UP,_UP,_UP,							// 0x40 - 0x4F
	_UP,_UP,_UP,_UP,_UP,_UP,_UP,_UP,_UP,_UP,_UP,_SE,_SE,_SE,_TO,_TO,							// 0x50 - 0x5F
	_TO,_LO,_LO,_LO,_LO,_LO,_LO,_LO,_LO,_LO,_LO,_LO,_LO,_LO,_LO,_LO,							// 0x60 - 0x6F
	_LO,_LO,_LO,_LO,_LO,_LO,_LO,_LO,_LO,_LO,_LO,_SE,_TO,_SE,_TO,_CT,							// 0x70 - 0x7F
	_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,							// 0x80 - 0x8F
	_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,							// 0x90 - 0x9F
	_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,							// 0xA0 - 0xAF
	_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,							// 0xB0 - 0xBF
	_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,							// 0xC0 - 0xCF
	_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,							// 0xD0 - 0xDF
	_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,							// 0xE0 - 0xEF
	_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,_OC,							// 0xF0 - 0xFF
};

enum HttpState {
	HS_UNKNOWN, HS_METHOD, HS_URL, HS_VERSION, HS_CODE, HS_REASON, HS_FIELD_NAME, HS_FIELD_VALUE, HS_EOL, HS_BODY, HS_CHLEN, HS_CHLENCR, HS_CHLENNL, HS_CHCR, HS_CHNL
};

#define	HS_CHUNKED		0x0001
#define	HS_LASTCHUNK	0x0002
#define	HS_LENGTHSET	0x0004

class Http : public IService
{
	friend class HttpParse;
	class HttpParse : public IService::Processor {
		Http&								mgr;
		HttpState							state;
		DynOArray<Value,PropertyID,ValCmp>	props;
		DynArray<MapElt>					fields;
		size_t								lmore;
		size_t								shift;
		unsigned							flags;
	public:
		HttpParse(Http& h,IServiceCtx *ctx,uint32_t f) : mgr(h),state((f&ISRV_REQUEST)!=0?HS_METHOD:(f&ISRV_RESPONSE)!=0?HS_VERSION:HS_UNKNOWN),props(ctx),fields(ctx),lmore(0),shift(0),flags(0) {}
		RC invoke(IServiceCtx *ctx,const Value& inp,Value& out,unsigned& mode) {
			if ((mode&ISRV_PROC_MASK)!=ISRV_READ) return RC_INVPARAM;
			if (inp.isEmpty()||inp.length==0) {mode|=ISRV_EOM; return RC_OK;}
			if (!isString((ValueType)inp.type)) return RC_INVPARAM;
			const unsigned char *ptr=inp.bstr,*end=ptr+inp.length,*beg; size_t l; RC rc;
			KWTrie::KWIt *it; unsigned code,i; MapElt data; char *v; unsigned char ch,ch2;
			if (state>=HS_BODY) {assert(ptr+shift<end); ptr+=shift; shift=0; mode&=~ISRV_MOREOUT;}
			else {
				do switch (state) {
				default: assert(0);
				case HS_UNKNOWN:			// we don't know if it's a request or response, determine from content
					mode&=~(ISRV_REQUEST|ISRV_RESPONSE);
					if (size_t(end-ptr)>=sizeof(HTTP_VERSION) && memcmp(ptr,HTTP_VERSION,sizeof(HTTP_VERSION)-2)==0) {mode|=ISRV_RESPONSE; state=HS_VERSION; continue;}
					mode|=ISRV_REQUEST;
				case HS_METHOD:
					if (methods==NULL) return RC_INTERNAL;
					if ((rc=methods->createIt(ctx->getSession(),it))!=RC_OK) return rc;
					for (code=~0u; ptr<end && *ptr!=' ';) if ((rc=it->next(*ptr++,code))!=RC_OK) break;
					if (rc!=RC_OK || code==~0u) {
						// code 501 (or 405 for not implemented)
						return RC_CORRUPTED;
					}
					data.val.set(code); data.val.setPropID(mgr.props[HTTP_METHOD].uid);
					if ((rc=props+=data.val)!=RC_OK) return rc;
					state=HS_URL;
				case HS_URL:
					while (ptr<end && *ptr==' ') ptr++; if (ptr>=end) return RC_CORRUPTED;
					if (*ptr=='*') ptr++;
					else {
						beg=ptr; uint32_t prc0=~0u,lprcTotal=0,lprc=0; Value url[9]; uint32_t nurl=0;
						if (*ptr!='/') {
							url[0].set((char*)beg,0); url[0].setPropID(mgr.props[HTTP_URL_SCHEME].uid); nurl++;
							while (ptr<end && (charType[*ptr]>=_DI || *ptr=='.' || *ptr=='+' || *ptr=='-' || *ptr=='~')) ptr++;
							if ((url[0].length=uint32_t(ptr-beg))==0 || ptr>=end || *ptr++!=':') return RC_CORRUPTED;
							if (ptr+1<end && ptr[0]=='/' && ptr[1]=='/') {
								url[1].set(ptr+=2,0); url[1].setPropID(mgr.props[HTTP_URL_HOST].uid); nurl++;
								for (; ptr<end && charType[*ptr]>_SP && *ptr!='/'; ptr++) switch (*ptr) {
								case '%':
									if (prc0==~0u) prc0=uint32_t(ptr-beg);
									if (++ptr>=end) return RC_CORRUPTED;
									if (*ptr=='%') lprc++;
									else {
										HTTPCharType ty=charType[*ptr]; lprc+=2;
										if (ty<_DI || (ty==_UP && *ptr>'F') || (ty==_LO && *ptr>'f') || ++ptr>=end) return RC_CORRUPTED;
										if ((ty=charType[*ptr])<_DI || (ty==_UP && *ptr>'F') || (ty==_LO && *ptr>'f')) return RC_CORRUPTED;
									}
									break;
								case '@':
									if (nurl>3) return RC_CORRUPTED;
									url[1].setPropID(mgr.props[HTTP_URL_USERNAME].uid);
									if (nurl>=3) url[2].setPropID(mgr.props[HTTP_URL_PASSWORD].uid);
								case ':':
									if (url[nurl-1].property==mgr.props[HTTP_URL_PORT].uid) return RC_CORRUPTED;
									if ((url[nurl-1].length=uint32_t(ptr-url[nurl-1].bstr)-lprc)==0) return RC_CORRUPTED;
									url[nurl].set((char*)(ptr+1),0); url[nurl].setPropID(mgr.props[*ptr==':'?HTTP_URL_PORT:HTTP_URL_HOST].uid);
									nurl++; lprcTotal+=lprc; lprc=0; ptr++; break;
								default:
									// check acceptable
									break;
								}
								if ((url[nurl-1].length=uint32_t(ptr-url[nurl-1].bstr)-lprc)==0) return RC_CORRUPTED;
								lprcTotal+=lprc; lprc=0;
							}
						}
						if (ptr<end && *ptr=='/') {
							url[nurl].set((char*)ptr++,0); url[nurl].setPropID(mgr.props[HTTP_URL_PATH].uid); nurl++;
							for (; ptr<end && charType[*ptr]>_SP; ptr++) switch (*ptr) {
							case '%':
								if (prc0==~0u) prc0=uint32_t(ptr-beg);
								if (++ptr>=end) return RC_CORRUPTED;
								if (*ptr=='%') lprc++;
								else {
									HTTPCharType ty=charType[*ptr]; lprc+=2;
									if (ty<_DI || (ty==_UP && *ptr>'F') || (ty==_LO && *ptr>'f') || ++ptr>=end) return RC_CORRUPTED;
									if ((ty=charType[*ptr])<_DI || (ty==_UP && *ptr>'F') || (ty==_LO && *ptr>'f')) return RC_CORRUPTED;
								}
								break;
							case '?':
							case '#':
								if ((url[nurl-1].length=uint32_t(ptr-url[nurl-1].bstr)-lprc)==0) return RC_CORRUPTED;
								url[nurl].set((char*)(ptr+1),0); url[nurl].setPropID(mgr.props[*ptr=='?'?HTTP_URL_QUERY:HTTP_URL_FRAGMENT].uid);
								if (url[nurl-1].property>=url[nurl].property) return RC_CORRUPTED;
								nurl++; lprcTotal+=lprc; lprc=0;
								if (*ptr++=='?' && ptr<end && memchr(ptr,'=',end-ptr)!=NULL) {
									DynArray<MapElt> qparts(ctx); bool fName=true; unsigned char *buf=NULL,*pb=NULL; MapElt me; rc=RC_OK;
									if (memchr(ptr,'%',end-ptr)!=NULL && (buf=pb=(unsigned char*)ctx->malloc(end-ptr))==NULL) return RC_NOMEM;
									for (const unsigned char *q=ptr,*beg=pb!=NULL?(const unsigned char*)pb:ptr;;q++) {
										bool fEnd=q>=end || charType[*q]<=_SP;
										if (fEnd || !fName && *q=='&') {
											if (!fName) {me.val.set(beg,(pb!=NULL?pb:q)-beg); beg=pb!=NULL?pb:q+1; fName=true; if ((rc=qparts+=me)!=RC_OK) break;}
											if (fEnd) break;
										} else if (*q=='%' && q+1<end) {
											assert(pb!=NULL);
											if (q[1]=='%') {*pb++='%'; q++;}
											else if (q+2<end) {
												ch=q[1]; ch2=q[2]; q+=2;
												*pb++=(ch<='9'?ch-'0':ch<='F'?ch-'A'+10:ch-'a'+10)<<4|(ch2<='9'?ch2-'0':ch2<='F'?ch2-'A'+10:ch2-'a'+10);
											}
										} else if (fName && *q=='=') {
											me.key.set(beg,(pb!=NULL?pb:q)-beg); beg=pb!=NULL?pb:q+1; fName=false;
										} else if (pb!=NULL) *pb++=*q;
									}
									if (rc==RC_OK && (unsigned)qparts!=0) {
										IMap *qmap=NULL;
										if ((rc=ctx->getSession()->createMap(&qparts[0],qparts,qmap,true))==RC_OK)
											{data.val.set(qmap); data.val.setPropID(mgr.props[HTTP_URL_QUERY_PARTS].uid); rc=props+=data.val;}
									}
									if (buf!=NULL) ctx->free(buf); if (rc!=RC_OK) return rc;
								}
								break;
							default:
								// check acceptable
								break;
							}
							if ((url[nurl-1].length=uint32_t(ptr-url[nurl-1].bstr)-lprc)==0) return RC_CORRUPTED;
							lprcTotal+=lprc; lprc=0;
						}
						size_t ll=size_t(ptr-beg); l=ll-lprcTotal;
						if (lprcTotal==0) {v=(char*)beg; mode|=ISRV_REFINP;}
						else if ((v=(char*)ctx->malloc(l+1))==NULL) return RC_NOMEM;
						else {
							unsigned j=0,k=0;
							for (unsigned i=0; i<ll; i++,j++) {
								if (k<nurl && url[k].bstr==beg+i) url[k++].str=v+j;
								if ((v[j]=beg[i])=='%' && i+1<ll) {
									if ((beg[i+1])=='%') i++;
									else if (i+2<ll) {
										ch=beg[i+1]; ch2=beg[i+2]; i+=2;
										v[j]=(ch<='9'?ch-'0':ch<='F'?ch-'A'+10:ch-'a'+10)<<4|(ch2<='9'?ch2-'0':ch2<='F'?ch2-'A'+10:ch2-'a'+10);
									}
								}
							}
							v[j]='\0'; assert(j==l);
						}
						data.val.setStruct(url,nurl); data.val.setPropID(mgr.props[HTTP_URL].uid);
						if ((rc=props+=data.val)!=RC_OK) return rc;
					}
					if (ptr>=end || charType[*ptr]!=_SP) return RC_CORRUPTED;
					state=HS_VERSION;
				case HS_VERSION:
					while (ptr<end && *ptr==' ') ptr++;
					if (size_t(end-ptr)<sizeof(HTTP_VERSION) || memcmp(ptr,HTTP_VERSION,sizeof(HTTP_VERSION)-2)!=0 || (*(ptr+sizeof(HTTP_VERSION)-2)!='0' && *(ptr+sizeof(HTTP_VERSION)-2)!='1')) {
						// if ((mode&ISRV_RESPONSE)==0) short-cut: 505 HTTP version not supported else ???
						return RC_CORRUPTED;
					}
					ptr+=sizeof(HTTP_VERSION)-1;
					if ((mode&ISRV_RESPONSE)==0) state=HS_EOL; else {state=HS_CODE; break;}
				case HS_EOL:
					while (ptr<end && *ptr==' ') ptr++;	//???
					if (ptr+2>end || ptr[0]!='\r' || ptr[1]!='\n') return RC_CORRUPTED;
					for (ptr+=2; ptr+2<=end && ptr[0]=='\r' && ptr[1]=='\n'; ptr+=2) state=HS_BODY;
					if (state==HS_BODY) continue;
					state=HS_FIELD_NAME;
				case HS_FIELD_NAME:
					for (beg=ptr; ptr<end; ptr++) if (charType[*ptr]<=_SE) break;
					if (ptr>=end || *ptr!=':') return RC_CORRUPTED;
					data.key.set((char*)beg,(uint32_t)(ptr-beg));
					if (rqHeaders->find((char*)beg,size_t(ptr-beg),code)!=RC_OK) code=~0u;
					ptr++; state=HS_FIELD_VALUE;
				case HS_FIELD_VALUE:
					while (ptr<end && *ptr==' ') ptr++; if (ptr==end) return RC_CORRUPTED;
					for (beg=ptr; ptr<end && charType[*ptr]>=_SP;) ptr++;
					if (ptr+1>=end || ptr[0]!='\r' || ptr[1]!='\n') return RC_CORRUPTED;
					if (ptr+2<end && (ptr[3]==' ' || ptr[3]=='\t')) {
						// LWS
					}
					data.val.set((char*)beg,(uint32_t)(ptr-beg)); mode|=ISRV_REFINP;
					if (code!=~0u && (code&0x80000000)!=0 || code<HTTP_HTTP_FIELDS) {
						data.val.setPropID((code&0x80000000)!=0?URIID(code&0x7FFFFFFF):mgr.props[code].uid);
						if ((rc=props+=data.val)!=RC_OK) return rc;
						if (data.val.property==PROP_SPEC_CONTENTLENGTH) {
							if ((rc=ctx->getSession()->convertValue(data.val,data.val,VT_UINT))!=RC_OK) return RC_CORRUPTED;
							lmore=data.val.ui; if ((flags&HS_CHUNKED)==0) flags|=HS_LENGTHSET;
						}
					} else if ((rc=fields+=data)==RC_OK) {
						switch (code) {
						default: break;
						case HTTP_TRANSFER_ENCODING:
							if (data.val.length==sizeof(HTTP_CHUNKED)-1 && !memcmp(data.val.str,HTTP_CHUNKED,sizeof(HTTP_CHUNKED)-1)) flags=HS_CHUNKED;
							break;
						case HTTP_CONNECTION:
							if (data.val.length==sizeof(HTTP_KEEPALIVE)-1 && !memcmp(data.val.str,HTTP_KEEPALIVE,sizeof(HTTP_KEEPALIVE)-1)) ctx->setKeepalive(true);
							break;
						}
					} else return rc;
					state=HS_EOL; break;
				case HS_CODE:
					while (ptr<end && *ptr==' ') ptr++;
					for (i=code=0; i<3; i++) {
						if (ptr>=end || unsigned(*ptr-'0')>unsigned('9'-'0')) return RC_CORRUPTED;
						code=code*10+*ptr++-'0';
					}
					data.val.set(code); data.val.setPropID(mgr.props[HTTP_CODE].uid);
					if ((rc=props+=data.val)!=RC_OK) return rc;
					state=HS_REASON;
				case HS_REASON:
					while (ptr<end && *ptr==' ') ptr++;
					for (beg=ptr;;ptr++) if (ptr+1>=end) return RC_CORRUPTED; else if (ptr[0]=='\r' && ptr[1]=='\n') break;
					data.val.set((char*)beg,uint32_t(ptr-beg)); data.val.setPropID(mgr.props[HTTP_REASON].uid); mode|=ISRV_REFINP;
					if ((rc=props+=data.val)!=RC_OK) return rc;
					state=HS_EOL; break;
				case HS_BODY:
					break;
				} while (state!=HS_BODY);
				uint32_t nFields=0; const MapElt *flds=fields.get(nFields); IMap *fmap;
				if (flds!=NULL && nFields!=0) {
					if ((rc=ctx->getSession()->createMap(flds,nFields,fmap,false))!=RC_OK) return rc;
					data.val.set(fmap); data.val.setPropID(mgr.props[(mode&ISRV_RESPONSE)!=0?HTTP_RESPONSE_FIELDS:HTTP_REQUEST_FIELDS].uid);
					if ((rc=props+=data.val)!=RC_OK) return rc;
				}
				uint32_t nProps=0; const Value *prps=props.get(nProps);
				if (prps!=NULL && nProps!=0) {
					rc=ctx->getCtxPIN()->modify(prps,nProps);
					// free ???
					if (rc!=RC_OK) return rc;
				}
				ctx->setReadMode(flags!=0); if ((flags&HS_CHUNKED)!=0) {state=HS_CHLEN; lmore=0;}
			}
			for (l=size_t(end-ptr); l!=0; l--) switch (state) {
			case HS_BODY:
				if (lmore>l) lmore-=l;
				else if ((flags&HS_CHUNKED)==0) {if ((flags&HS_LENGTHSET)!=0) {mode|=ISRV_EOM; l=lmore; lmore=0;}}
				else {assert(lmore!=0); state=HS_CHCR; l=lmore; lmore=0; mode|=ISRV_KEEPINP|ISRV_MOREOUT; shift=size_t(ptr+l-inp.bstr);}
				out.set(ptr,uint32_t(l)); mode|=ISRV_REFINP; return RC_OK;
			case HS_CHCR: if (*ptr++!='\r') return RC_CORRUPTED; state=HS_CHNL; break;
			case HS_CHLENCR: if (*ptr++!='\r') return RC_CORRUPTED; state=HS_CHLENNL; break;
			case HS_CHNL: if (*ptr++!='\n') return RC_CORRUPTED; if ((flags&HS_LASTCHUNK)!=0) {mode|=ISRV_EOM; return RC_OK;} state=HS_CHLEN; lmore=0; break;
			case HS_CHLENNL: if (*ptr++!='\n') return RC_CORRUPTED; state=(flags&HS_LASTCHUNK)!=0?HS_CHCR:HS_BODY; break;
			case HS_CHLEN:
				ch=*ptr++;
				if (unsigned(ch-'0')<=9u) lmore=(lmore<<4)+ch-'0';
				else if (unsigned(ch-'A')<=5u) lmore=(lmore<<4)+ch-'A'+10;
				else if (unsigned(ch-'a')<=5u) lmore=(lmore<<4)+ch-'a'+10;
				else if (ch=='\r') {state=HS_CHLENNL; if (lmore==0) flags|=HS_LASTCHUNK;}
				else return RC_CORRUPTED;
				break;
			}
			mode|=flags!=0?ISRV_NEEDMORE:ISRV_EOM;
			return RC_OK;
		}
	};
	friend class HttpRender;
	class HttpRender : public IService::Processor {
		Http&		mgr;
		unsigned	flags;
	public:
		HttpRender(Http& h) : mgr(h),flags(0) {}
		RC invoke(IServiceCtx *ctx,const Value& inp,Value& out,unsigned& mode) {
			RC rc; const Value *flds=NULL; unsigned nFlds=0;
			if ((mode&ISRV_PROC_MASK)!=ISRV_WRITE || !isString((ValueType)out.type) ||
				out.str==NULL || out.length<HTTP_DEFAULT_HEADER+HTTP_DEFAULT_TRAILER) return RC_INVPARAM;
			if ((mode&ISRV_ERROR)!=0) {
				// inp.ui -> rc
			} else if ((flags&HS_CHUNKED)==0) {
				char *p=(char*)out.str+HTTP_DEFAULT_HEADER; size_t left=HTTP_DEFAULT_HEADER-2; 
				out.length-=HTTP_DEFAULT_TRAILER; *--p='\n'; *--p='\r'; unsigned n=out.length-HTTP_DEFAULT_HEADER;
				const Value *pv=flds!=NULL?Value::find(PROP_SPEC_CONTENTLENGTH,flds,nFlds):ctx->getParameter(PROP_SPEC_CONTENTLENGTH);
				if (pv!=NULL && isInteger((ValueType)pv->type) || (pv=NULL,mode&ISRV_EOM)!=0 || n==0) {
					uint64_t cl=pv!=NULL?pv->type>=VT_INT64?pv->ui64:pv->ui:n; mode|=ISRV_SKIP;
					if (pv!=NULL || cl!=0ULL) {
						char buf[20],*q=buf+sizeof(buf)-1; q[0]=0; do *--q=char(cl%10+'0'); while ((cl/=10)!=0);
						Value v; v.set(q,size_t(sizeof(buf)-1-(q-buf)));
						if ((rc=addHeaderField(HTTP_CONTLEN,sizeof(HTTP_CONTLEN)-1,&v,p,left,out,ctx))!=RC_OK) return rc;
					}
				} else {
					flags|=HS_CHUNKED; p[n+2]='\r'; p[n+3]='\n'; out.length+=2;
					do {uint8_t ch=n&0xF; *--p=ch<10?ch+'0':ch+'A'-10; --left;} while ((n>>=4)!=0);
					*--p='\n'; *--p='\r'; left-=2; Value v; v.set(HTTP_CHUNKED,sizeof(HTTP_CHUNKED)-1);
					if ((rc=addHeaderField(HTTP_TRENC,sizeof(HTTP_TRENC)-1,&v,p,left,out,ctx))!=RC_OK) return rc;
				}
				pv=flds!=NULL?Value::find(PROP_SPEC_CONTENTTYPE,flds,nFlds):ctx->getParameter(PROP_SPEC_CONTENTTYPE);
				if (pv!=NULL && pv->type==VT_STRING && (rc=addHeaderField(HTTP_CONTTYPE,sizeof(HTTP_CONTTYPE)-1,pv,p,left,out,ctx))!=RC_OK) return rc;
				URIID uid=mgr.props[(mode&ISRV_RESPONSE)!=0?HTTP_RESPONSE_FIELDS:HTTP_REQUEST_FIELDS].uid; uint64_t fieldMask=0ULL;
				if ((pv=flds!=NULL?Value::find(uid,flds,nFlds):ctx->getParameter(uid))!=NULL) {
					if (pv->type==VT_STRING) {
						if (left<pv->length) {if ((rc=ctx->expandBuffer(out,pv->length))!=RC_OK) return rc;}		//????? checkLength(...), adjust left,p
						memcpy(p-=pv->length,pv->str,pv->length); left-=pv->length;
					} else if (pv->type==VT_MAP) {
						unsigned mode=IMAP_FIRST|IMAP_REVERSE,code;
						for (const Value *fn,*fv; pv->map->getNext(fn,fv,mode)==RC_OK; mode=IMAP_REVERSE) {
							if (fn==NULL || fn->type!=VT_STRING || fv==NULL || fv->type!=VT_STRING) return RC_INVPARAM;
							if ((rc=addHeaderField(fn->str,fn->length,fv,p,left,out,ctx))!=RC_OK) return rc;
							if (rqHeaders->find(fn->str,fn->length,code)==RC_OK && (code&0x80000000)==0 && code>=HTTP_HTTP_FIELDS) fieldMask|=1ULL<<(code-HTTP_HTTP_FIELDS);
						}
					} else return RC_TYPE;
				}
				if ((mode&ISRV_RESPONSE)!=0) {
					// add date, user agent if not set
					unsigned code=HTTP_CODE_OK; const char *reason=HTTP_REASON_OK; char cbuf[20]; size_t lc=0,lr=0;
					pv=flds!=NULL?Value::find(mgr.props[HTTP_CODE].uid,flds,nFlds):ctx->getParameter(mgr.props[HTTP_CODE].uid);
					if (pv!=NULL && (pv->type==VT_UINT || pv->type==VT_INT && pv->i>=0)) {
						code=pv->ui; const ResponseCode *rc=strResponses;
						for (unsigned nv=sizeof(strResponses)/sizeof(strResponses[0]); nv!=0; ) {
							unsigned k=nv>>1; const ResponseCode *q=&rc[k]; 
							if (q->code<code) {nv-=++k; rc+=k;} else if (q->code>code) nv=k; else {reason=q->reason; break;}
						}
					}
					pv=flds!=NULL?Value::find(mgr.props[HTTP_REASON].uid,flds,nFlds):ctx->getParameter(mgr.props[HTTP_REASON].uid);
					if (pv!=NULL && pv->type==VT_STRING) {reason=pv->str; lr=pv->length;}
					else if (reason!=NULL) lr=strlen(reason); else {reason=""; lr=0;}
					lc=sprintf(cbuf,"%d ",code);
					if (left<sizeof(HTTP_VERSION)+lc+lr+2 && (rc=ctx->expandBuffer(out))!=RC_OK) return rc;
					*--p='\n'; *--p='\r'; memcpy(p-=lr,reason,lr); memcpy(p-=lc,cbuf,lc);
					memcpy(p-=sizeof(HTTP_VERSION),HTTP_VERSION " ",sizeof(HTTP_VERSION)); left-=sizeof(HTTP_VERSION)+lc+lr+2;
				} else {
					// add date, host, accept... if not set
					if ((rc=add(" " HTTP_VERSION "\r\n",sizeof(HTTP_VERSION)+2,p,left,out,ctx))!=RC_OK) return rc;
					pv=flds!=NULL?Value::find(mgr.props[HTTP_URL_QUERY_PARTS].uid,flds,nFlds):ctx->getParameter(mgr.props[HTTP_URL_QUERY_PARTS].uid);
					if (pv!=NULL && pv->type==VT_MAP) {
						const Value *nm,*val;
						for (bool fFirst=true; pv->map->getNext(nm,val,fFirst)==RC_OK; fFirst=false) 
							if (nm!=NULL && nm->type==VT_STRING && val!=NULL && val->type==VT_STRING) {
								if (!fFirst && (rc=add("&",1,p,left,out,ctx))!=RC_OK) return rc;
								if ((rc=add(val->str,val->length,p,left,out,ctx,true))!=RC_OK) return rc;
								if ((rc=add("=",1,p,left,out,ctx))!=RC_OK) return rc;
								if ((rc=add(nm->str,nm->length,p,left,out,ctx,true))!=RC_OK) return rc;
							}
							if ((rc=add("?",1,p,left,out,ctx))!=RC_OK) return rc;
					} else if ((pv=flds!=NULL?Value::find(mgr.props[HTTP_URL_QUERY].uid,flds,nFlds):ctx->getParameter(mgr.props[HTTP_URL_QUERY].uid))!=NULL && pv->type==VT_STRING) {
						if ((rc=add(pv->str,pv->length,p,left,out,ctx))!=RC_OK) return rc;
						if ((rc=add("?",1,p,left,out,ctx))!=RC_OK) return rc;
					}
					const char *q="/"; size_t lq=1;
					pv=flds!=NULL?Value::find(mgr.props[HTTP_URL].uid,flds,nFlds):ctx->getParameter(mgr.props[HTTP_URL].uid);
					if (pv!=NULL && pv->type==VT_STRING && pv->length!=0) {q=pv->str; lq=pv->length;}
					if (q[lq-1]!='/' && *p=='?' && (rc=add("/",1,p,left,out,ctx))!=RC_OK) return rc;
					if ((rc=add(q,lq,p,left,out,ctx))!=RC_OK) return rc;
					if ((rc=add(" ",1,p,left,out,ctx))!=RC_OK) return rc;
					pv=flds!=NULL?Value::find(mgr.props[HTTP_METHOD].uid,flds,nFlds):ctx->getParameter(mgr.props[HTTP_METHOD].uid);
					if (pv!=NULL && pv->type==VT_STRING && pv->length!=0) {q=pv->str; lq=pv->length;}
					else {q=strMethods[pv!=NULL&&pv->type==VT_ENUM&&pv->enu.enumid==mgr.props[HTTP_METHOD].uid&&pv->enu.eltid<sizeof(strMethods)/sizeof(strMethods[0])?pv->enu.eltid:HM_GET].kw; lq=strlen(q);}
					if ((rc=add(q,lq,p,left,out,ctx))!=RC_OK) return rc;
				}
				out.str=p; out.length-=left;
			} else {
				char *p=(char*)out.str+HTTP_DEFAULT_HEADER,*e=(char*)out.str+(out.length-=HTTP_DEFAULT_TRAILER);
				if (out.length>HTTP_DEFAULT_HEADER) {
					*--p='\n'; *--p='\r'; *e++='\r'; *e++='\n'; unsigned n=out.length-HTTP_DEFAULT_HEADER;
					do {uint8_t ch=n&0xF; *--p=ch<10?ch+'0':ch+'A'-10;} while ((n>>=4)!=0);
				}
				if ((mode&ISRV_EOM)!=0||out.length==HTTP_DEFAULT_HEADER)
					{memcpy(e,HTTP_ENDCHUNK,sizeof(HTTP_ENDCHUNK)-1); e+=sizeof(HTTP_ENDCHUNK)-1;}
				out.str=p; out.length=uint32_t(e-p);
			}
			return RC_OK;
		}
		RC addHeaderField(const char *fn,size_t ln,const Value *fv,char *&p,size_t& left,Value& out,IServiceCtx *ctx) {
			size_t l=ln+2+fv->length+2;
			if (left<l) {
				RC rc; if ((rc=ctx->expandBuffer(out,l))!=RC_OK) return rc;
				// adjust left,p
			}
			p[-1]='\n'; p[-2]='\r'; p-=fv->length+2; memcpy(p,fv->str,fv->length);
			p[-1]=' '; p[-2]=':'; p-=ln+2; memcpy(p,fn,ln); left-=l; return RC_OK;
		}
		RC add(const char *str,size_t l,char *&p,size_t& left,Value& out,IServiceCtx *ctx,bool fEnc=false) {
			size_t extra=0; uint8_t ch;
			if (fEnc) for (const uint8_t *q=(uint8_t*)str,*end=q+l; q<end; q++)
				if (charType[*q]<=_SE||*q=='&'||*q=='=') extra+=2; else if (*q=='%') extra++;
			if (left<l+extra) {
				RC rc; if ((rc=ctx->expandBuffer(out,l+extra))!=RC_OK) return rc;
				// adjust left,p
			}
			if (extra==0) {if (l==1) *--p=*str; else memcpy(p-=l,str,l); left-=l;}
			else for (const char *q=str+l; --q>=str;) {
				if ((ch=*q)=='%') {p[-1]=p[-2]='%'; p-=2; left-=2;} else if (charType[ch]>_SE&&ch!='&'&&ch!='=') {*--p=ch; --left;}
				else {p[-1]=(ch&0xF)>=10?(ch&0xF)+'A'-10:(ch&0xF)+'0'; p[-2]=(ch>>4)>=10?(ch>>4)+'A'-10:(ch>>4)+'0'; p[-3]='%'; p-=3; left-=3;}
			}
			return RC_OK;
		}
	};
	const	URIMap	*props;
public:
	Http(URIMap *um) : props(um) {}
	~Http() {}
	RC create(IServiceCtx *ctx,uint32_t& dscr,Processor *&ret) {
		switch (dscr&ISRV_PROC_MASK) {
		default: return RC_INVOP;
		case ISRV_READ:
			if ((ret=new(ctx) HttpParse(*this,ctx,dscr))==NULL) return RC_NOMEM;
			break;
		case ISRV_WRITE:
			if ((ret=new(ctx) HttpRender(*this))==NULL) return RC_NOMEM;
			dscr|=ISRV_ENVELOPE|ISRV_ERROR; break;
		}
		return RC_OK;
	}
	void getEnvelope(size_t& lHeader,size_t& lTrailer) const {
		lHeader=HTTP_DEFAULT_HEADER; lTrailer=HTTP_DEFAULT_TRAILER;
	}
	void getSocketDefaults(int& proto,uint16_t& port) const {
		proto=IPPROTO_TCP; port=80;
	}
};

};

using namespace AfyHttp;

extern "C" AFY_EXP bool SERVICE_INIT(HTTP)(ISession *ses,const Value *pars,unsigned nPars,bool fNew)
{
	IAffinity *ctx=ses->getAffinity();

	if (methods==NULL && KWTrie::createTrie(strMethods,sizeof(strMethods)/sizeof(strMethods[0]),methods)!=RC_OK) return false;
	if (rqHeaders==NULL) {
		if (KWTrie::createTrie(strGeneralHeaders,sizeof(strGeneralHeaders)/sizeof(strGeneralHeaders[0]),rqHeaders)!=RC_OK) return false;
		if (rqHeaders->addKeywords(strRequestHeaders,sizeof(strRequestHeaders)/sizeof(strRequestHeaders[0]))!=RC_OK) return false;
		if (rqHeaders->addKeywords(strEntityHeaders,sizeof(strEntityHeaders)/sizeof(strEntityHeaders[0]))!=RC_OK) return false;
	}
	if (rsHeaders==NULL) {
		if (KWTrie::createTrie(strGeneralHeaders,sizeof(strGeneralHeaders)/sizeof(strGeneralHeaders[0]),rsHeaders)!=RC_OK) return false;
		if (rsHeaders->addKeywords(strResponseHeaders,sizeof(strResponseHeaders)/sizeof(strResponseHeaders[0]))!=RC_OK) return false;
		if (rsHeaders->addKeywords(strEntityHeaders,sizeof(strEntityHeaders)/sizeof(strEntityHeaders[0]))!=RC_OK) return false;
	}

	URIMap *pmap=(URIMap*)ctx->malloc(sizeof(propURIs)/sizeof(propURIs[0])*sizeof(URIMap)); if (pmap==NULL) return false;
	for (unsigned i=0; i<sizeof(propURIs)/sizeof(propURIs[0]); i++) {pmap[i].URI=propURIs[i]; pmap[i].uid=0;}
	if (ses->mapURIs(sizeof(propURIs)/sizeof(propURIs[0]),pmap)!=RC_OK) return false;

	void *p=ctx->malloc(sizeof(Http)); if (p==NULL) return false;
	if (ctx->registerService(HTTP_SERVICE_NAME,new(p) Http(pmap))!=RC_OK) return false;

	ctx->registerPrefix("http",4,HTTP_PROP_NAME "/",sizeof(HTTP_PROP_NAME));

	if (fNew) {
		static const unsigned nElts=sizeof(strMethods)/sizeof(strMethods[0]); Value elts[nElts],props[2];
		for (unsigned i=0; i<nElts; i++) {elts[i].set(strMethods[i].kw); elts[i].eid=strMethods[i].val;}
		props[0].setURIID(pmap[HTTP_METHOD].uid); props[0].setPropID(PROP_SPEC_OBJID);
		props[1].set(elts,nElts); props[1].setPropID(PROP_SPEC_ENUM);
		RC rc=ses->createPIN(props,2,NULL,MODE_COPY_VALUES|MODE_PERSISTENT|MODE_FORCE_EIDS);
		if (rc!=RC_OK && rc!=RC_ALREADYEXISTS) {
			report(MSG_ERROR,"HTTP service: failed to register Methods enum (%d)\n",rc);
			// return false;
		}
	}
	return true;
}
