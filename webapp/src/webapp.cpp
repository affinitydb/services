/*
Copyright (c) 2004-2014 GoPivotal, Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,  WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
*/

#ifdef _MSC_VER
#ifndef _WIN32_WINNT                
#define _WIN32_WINNT _WIN32_WINNT_VISTA
#endif						
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#define _strnicmp				strncasecmp
#define	HANDLE					int
#define	INVALID_HANDLE_VALUE	(-1)
#endif

#include <affinity.h>
#ifndef WIN32
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <set>

#include "../../xml/src/serialization.h" // tmp (debugging)

#define WEBAPPSERVICE_NAME AFFINITY_SERVICE_PREFIX "webapp"

using namespace Afy;

typedef std::set<std::string> TStrings;

#define	HTTP_BAD_REQUEST	400
#define	HTTP_NO_ACCESS		403
#define	HTTP_NOT_FOUND		404
#define	HTTP_SERVER_ERROR	500

enum ePropIndex
{
	kPISTART = 0,
	kPIParameterPaths = kPISTART,
	kPIParameterModes,
	kPIPathName,
	kPIContent,
	kPIHttpUrl,
	kPIHttpUrlPath,
	kPIHttpUrlQueryParts,
	kPIHttpResponseCode,
	kPIHttpResponseFields,
	kPIENUM_MODES,
	kPITOTAL
};

const static char *sProps[] =
{
	WEBAPPSERVICE_NAME "/config/paths",
	WEBAPPSERVICE_NAME "/config/modes",
	WEBAPPSERVICE_NAME "/doc/pathname",
	WEBAPPSERVICE_NAME "/doc/content",
	AFFINITY_SERVICE_PREFIX "HTTP/url",
	AFFINITY_SERVICE_PREFIX "HTTP/url/path",
	AFFINITY_SERVICE_PREFIX "HTTP/url/queryParts",
	AFFINITY_SERVICE_PREFIX "HTTP/code",
	AFFINITY_SERVICE_PREFIX "HTTP/response/fields",
	/*WEBAPPSERVICE_NAME"MODES"*/"WEBAPPMODES",
};

class WebappService : public IService
{
	protected:
		friend class WebappServiceProc;
		class WebappServiceProc : public IService::Processor
		{
			protected:
				WebappService& mService; // Back-reference to the service.
				TStrings	mPaths; // Configured paths on disk where to retrieve files from (optional).
				uint32_t	mModes;
				HANDLE		mFile;
				uint64_t	mFileSize;
				uint64_t	mCurPos;
				bool		fFirst;
			public:
				WebappServiceProc(WebappService & pService, IServiceCtx * pCtx)
					: mService(pService)
					, mModes(0)
					, mFile(INVALID_HANDLE_VALUE)
					, mFileSize(0ULL)
					, mCurPos(0ULL)
					, fFirst(true)
				{
					report(AfyRC::MSG_DEBUG,"Created a WebappServiceProc(%p)\n", this);
					readServiceConfig(pCtx); // Note: we can cache the service pin's parameters here, because we use ISRV_NOCACHE.
				}
				virtual ~WebappServiceProc()
				{
					if (INVALID_HANDLE_VALUE != mFile)
#ifdef WIN32
						::CloseHandle(mFile);
#else
						close(mFile);
#endif
				}
				virtual RC invoke(IServiceCtx *ctx,const Value& inp,Value& out,unsigned& mode)
				{
					report(AfyRC::MSG_DEBUG, "WebappServiceProc::invoke(%p)\n", this);
					if ((mode&(ISRV_PROC_MASK|ISRV_SERVER))!=(ISRV_READ|ISRV_SERVER)) return RC_INVPARAM;

					if (out.isEmpty() || 0!=(mode&ISRV_NEEDFLUSH)) return RC_INVPARAM;

					mode&=~ISRV_EOM;	// a server must initially reset ISRV_EOM

					if (fFirst)
					{
						fFirst = false;

						// Get the path of the request.

						Value const * const lUrlVal = ctx->getCtxPIN()->getValue(mService.mProps[kPIHttpUrl].uid), *lPathVal = NULL;
						if (NULL != lUrlVal && VT_STRUCT == lUrlVal->type)
							lPathVal = Value::find(mService.mProps[kPIHttpUrlPath].uid,lUrlVal->varray,lUrlVal->length);

						if (!lPathVal || VT_STRING != lPathVal->type)
						{
							setCode(HTTP_BAD_REQUEST,ctx);
							out.length=0; mode|=ISRV_EOM;
							return RC_OK;
						}
#if 0
						if (strstr(lPathVal->str, "/db") == lPathVal->Str) // improve
						{
							Value const * const lQueryParts = ctx->getCtxPIN()->getValue(mService.mProps[kPIHttpUrlQueryParts].uid);
							if (!lQueryParts || VT_MAP != lQueryParts->type)
								return RC_INVPARAM;
		
							Value const * const lPathVal = Value::find(mService.mProps[kPIHttpUrlQueryParts].uid,lUrlVal->varray,lUrlVal->length);
							for (int iQp = 0; iQp < lQueryParts->map->count(); iQp++)
							{
								Value const * lQpKey;
								Value const * lQpVal;
								if (RC_OK != lQueryParts->getNext(lQpKey, lQpVal, iQp==0))
									return RC_INVPARAM; // reporting // freeing
								if (VT_STRING != lQpKey->type || VT_STRING != lQpVal->type)
									return RC_INVPARAM; // reporting // freeing
								if (0 == strcmp(lQpKey->str, "q"))
									lQuery = lQpVal->str;
								// presumably this will ~simply do the same as srv:pathSQL...
								// and output format will imply a dynamic manipulation of the stack (or a switch statement) - tbd
								else if (0 == strcmp(lQpKey->str, "i"))
									lInputT = (lQpVal->str == strstr(lQpVal->str, "proto") ? kTPROTO: kTPATSHSQL;
								else if (0 == strcmp(lQpKey->str, "o"))
									lOutputT = (lQpVal->str == strstr(lQpVal->str, "proto") ? kTPROTO: kTJSON;
								// TODO: LIMIT, OFFSET, params, ...
							}
						}
						else
#endif

						std::string	mCurPath;

						if (fullPath(lPathVal->str, mCurPath))
						{
#ifdef WIN32
							mFile = ::CreateFile(mCurPath.c_str(),GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
							if (mFile!=INVALID_HANDLE_VALUE) {LARGE_INTEGER size; mFileSize=GetFileSizeEx(mFile,&size)?size.QuadPart:0;}
#else
							mFile = open(mCurPath.c_str(),O_RDONLY,S_IRUSR|S_IRGRP);
							if (mFile<0)
								mFile=INVALID_HANDLE_VALUE;
							else
							{
#if !defined(__arm__) && !defined(__APPLE__)
								struct stat64 fileStats;
								if (fstat64(mFile,&fileStats)==0)
									mFileSize=fileStats.st_size;
#else
								struct stat fileStats;
								if (fstat(mFile,&fileStats)==0)
									mFileSize=fileStats.st_size;
#endif
							}
#endif
						}
						if (INVALID_HANDLE_VALUE != mFile)
						{
							report(AfyRC::MSG_DEBUG, "WebappServiceProc::doRead(%p): ready to produce file %s\n", this, mCurPath.c_str());
							Value vFileSize; vFileSize.setU64(mFileSize); vFileSize.setPropID(PROP_SPEC_CONTENTLENGTH);
							ctx->getCtxPIN()->modify(&vFileSize,1);
						} else
						{
							report(AfyRC::MSG_WARNING, "WebappServiceProc::doRead(%p): could not find file %s\n", this, mCurPath.c_str());
							setCode(HTTP_NOT_FOUND,ctx);
							out.length=0; mode|=ISRV_EOM;
							return RC_OK;
						}

					}

					size_t const lMaxOut = out.length; out.length = 0;
					RC lRC = RC_OK;
#ifdef WIN32
					DWORD lRead;
					if (::ReadFile(mFile,(char*)out.str,lMaxOut,&lRead,NULL)==FALSE)
#else
					long const lRead = ::read(mFile,(char*)out.str,lMaxOut);
					if (lRead < 0) 
#endif
						lRC = ctx->getOSError();
					if (RC_OK == lRC)
					{
						out.length = (uint32_t) lRead;
						mCurPos += lRead;
						if (mCurPos < mFileSize)
							mode |= ISRV_MOREOUT;
						else
							mode = (mode & ~ISRV_MOREOUT) | ISRV_EOM;
					} else
					{
						setCode(HTTP_SERVER_ERROR,ctx);
						mode = (mode & ~ISRV_MOREOUT) | ISRV_EOM;
					}
					return RC_OK;
				}
			protected:
				void setCode(unsigned code,IServiceCtx *ctx)
				{
					Value v; v.set(code); 
					v.setPropID(mService.mProps[kPIHttpResponseCode].uid);
					ctx->getCtxPIN()->modify(&v,1);
				}
				void addPath(char const * pPath)
				{
					size_t const lPathLen = pPath ? strlen(pPath) : 0;
					if (0 == lPathLen)
						return;
					if (pPath[lPathLen - 1] == '/' || pPath[lPathLen - 1] == '\\')
						{ mPaths.insert(pPath); return; }
					std::string lPath = pPath;
					lPath += '/';
					mPaths.insert(lPath);
				}
				bool fullPath(char const * pRelativePath, std::string & pFull) const
				{
					for (TStrings::const_iterator iP = mPaths.begin(); mPaths.end() != iP; iP++)
					{
						pFull = *iP;
						pFull += pRelativePath;
						std::ifstream lIs(pFull.c_str());
						if (lIs.is_open())
							return true;
					}
					pFull = pRelativePath;
					std::ifstream lIs(pFull.c_str());
					if (lIs.is_open())
						return true;
					pFull.clear();
					return false;
				}
			protected:
				void readServiceConfig(IServiceCtx * pCtx)
				{
					Value const * const lPaths = pCtx->getParameter(mService.mProps[kPIParameterPaths].uid);
					if (lPaths)
					{
						switch (lPaths->type)
						{
							case VT_COLLECTION: { for (uint32_t i = 0; i < lPaths->length; i++) if (VT_STRING == lPaths->varray[i].type) addPath(lPaths->varray[i].str); break; }
							case VT_STRING: addPath(lPaths->str); break;
							default: report(AfyRC::MSG_DEBUG,"WebappServiceProc(%p): Unexpected type for %s: %d\n", this, mService.mProps[kPIParameterPaths].URI, lPaths->type); break;
						}
					}
					Value const * const lModes = pCtx->getParameter(mService.mProps[kPIParameterModes].uid);
					if (lModes)
					{
						switch (lModes->type)
						{
							case VT_COLLECTION: { for (uint32_t i = 0; i < lModes->length; i++) /*if (VT_ENUM == lModes->varray[i].type) mPaths.insert(lModes->varray[i].str);*/ break; }
							case VT_ENUM: /*mPaths.insert(lModes->str);*/ std::cout << "mode: " << lModes->uid << std::endl; break;
							default: report(AfyRC::MSG_DEBUG,"WebappServiceProc(%p): Unexpected type for %s: %d\n", this, mService.mProps[kPIParameterModes].URI, lModes->type); break;
						}
					}
				}
			protected:
#if 0
				// Note: One approach would be to simply use the code below, from the server;
				//       but this is not super-nice as it implies rewriting buffering logic that is already 
				//       in individual services (e.g. protobuf); better would be a dynamic/conditional
				//       service stack configuration, which Mark will be provide soon; in the meantime,
				//       Mark prefers that I emulate our old server via multiple ports (one for each
				//       static config, e.g. producing protobuf only, or JSON only, etc.)

				#define MAX_ALLOCA 10240
				#define ALLOCA( se, n, sz, yes )                                        \
						( (*(yes)=((n)*(sz)>MAX_ALLOCA) ) ? (se)->malloc( (n)*(sz) ) :       \
							alloca( (n)*(sz) ) )
				#define AFREE( se, yes, ptr ) \
						do { if ( (yes) && (ptr) ) { (se)->free(ptr); } } while (0)

				/**
				 * Same names/impl as server/src/storecmd.cpp.
				 */
				static RC afy_sql2json(ISession& sess, const char* pCmd, char*& pResult, size_t& len, char** params, unsigned nparams, unsigned off = 0, unsigned lim = ~0u)
				{
						report(AfyRC::MSG_DEBUG, "WebappServiceProc::afy_sql2json(%p): command=%s: %d\n", this, pCmd);
						CompilationError lCE;

						int alloc;
						Value* vals = (Value*)ALLOCA(&sess, nparams, sizeof(Value), &alloc);
						str2value(sess, vals, params, nparams);

						const RC rc = sess.execute(pCmd, strlen(pCmd), &pResult, NULL, 0, vals, nparams, &lCE, NULL, lim, off);
						AFREE(&sess, alloc, vals);
						if (RC_OK != rc)
						{
								report(AfyRC::MSG_WARNING, "error %d on command: %s\n", rc, pCmd);
								report(AfyRC::MSG_WARNING, "error: %s\n", lCE.msg);
								strerror( rc, sess, lCE, pResult, len );
						}
						return rc;
				}

				static size_t afy_sql2raw(ISession& sess, afy_stream_t* pCtx, const char* pCmd, char*& pResult, Twriter pWriter, char** params, unsigned nparams, unsigned offset = 0, unsigned limit = ~0u)
				{
						report(AfyRC::MSG_DEBUG,"WebappServiceProc::afy_sql2raw(%p): command=\n%s\n", pCmd); 
						CompilationError lCE;
						IStmt * const stmt = sess.createStmt(pCmd, NULL, 0, &lCE);
						if (!stmt)
						{
								char* err = NULL;
								size_t len;
								strerror( RC_SYNTAX, sess, lCE, err, len );
								report(AfyRC::MSG_WARNING, err);
								sess.free( err );
								return (ssize_t)-1;
						}

						int alloc;
						Value* vals = (Value*)ALLOCA( &sess, nparams, sizeof(Value), &alloc );
						str2value( sess, vals, params, nparams );
						IStreamOut* out = NULL;
						RC res = stmt->execute( out, vals, nparams, limit, offset );
						AFREE( &sess, alloc, vals );
						//if ( res == RC_SYNTAX && lCE.msg)
						//    printf("%*s\nSyntax: %s at %d, line %d\n", lCE.pos+2, "^", 
						//    lCE.msg, lCE.pos, lCE.line);
						ssize_t off = 0;
						if ( res != RC_OK ) {
								LOG_LINE(kLogError, "affinity error %d", res);
						} else {
								unsigned len = 0x1000;
								unsigned char* buf = (unsigned char*)sess.malloc( len );
								size_t got = len;
								if ( buf == NULL ) { 
										res = RC_OTHER; 
								} else {
										while ( !intr && (res = out->next(buf+off, got)) == RC_OK ) {
												off += got;
												if ( len - off < len/2 ) {
														len += len/2;
														buf = (unsigned char*)sess.realloc( buf, len );
														if ( buf == NULL ) { res = RC_OTHER; break; }
												}
												got = len - off;
										}
								}
								out->destroy();
								pResult = (char*)buf;
						}
						stmt->destroy();
						return (res == RC_OK || res == RC_EOF) ? off : size_t(-1);
				}

				class WriterIStreamIn : public IStreamIn
				{
					protected:
						Twriter writer;
						afy_stream_t* ctx;
					protected:
						WriterIStreamIn() {}
					public:
						WriterIStreamIn( Twriter& w, afy_stream_t* c ) { writer = w; ctx = c; }
						virtual RC next( const unsigned char *buf, size_t len ) {
								ssize_t wrote = writer( ctx, buf, len );
								if ( wrote < 0 || (size_t)wrote < len ) {
										return RC_OTHER;
								}
								return RC_OK;
						}
						virtual void destroy( void ) {}
				};

				static int afy_raw2raw(ISession& sess, afy_stream_t* ctx, Treader reader, Twriter writer)
				{
						IStreamIn *in = NULL;
						WriterIStreamIn out( writer, ctx );
						if ( !reader || sess.createInputStream( in, &out ) != RC_OK ) {
								return 0;
						}

						unsigned char buf[0x1000];
						ssize_t lRead = 1, got = 0, use, need;
						RC res = RC_OK;
						if ( ctx->len > 0 )
						{
								use = ctx->clen > 0 ? ( MIN( ctx->clen, ctx->len ) ) : ctx->len;
								res = in->next( (unsigned char*)ctx->buf, use );
								got += use;
								ctx->len -= use;
						}
						while ( !intr && res == RC_OK && lRead > 0 && ( ctx->clen >= 0 ? got < (ssize_t)ctx->clen : 1 ) )
						{
								need = ctx->clen >= got ? ctx->clen - got : sizeof(buf);
								lRead = reader( ctx, buf, MIN( need, (ssize_t)sizeof(buf) ) );
								if ( lRead > 0 )
								{
										got += lRead;
										res = in->next( buf, lRead );
								}
						}
						if ( lRead < 0 ) { res = RC_OTHER; }
						if ( res == RC_OK ) { res = in->next( NULL, 0 ); }
						in->destroy();

						return (res == RC_OK) ? 1 : 0;
				}

				static void str2value( ISession& sess, Value* vals, 
												char** params, unsigned nparams ) {
						RC rc;
		
						for ( unsigned i = 0; i < nparams; i++ ) {
								char* p = params[i];
								Value& v = vals[i];
								if ( !p ) {                 /* NULL */
										v.setError();
								} else {
										CompilationError lCE;
										/* the store kernel can do this now, so below code obsoleted */
										rc = sess.parseValue( p, strlen(p), v, &lCE );
										if ( rc != RC_OK ) { v.setError(); }
								} 
						}
				}
				void strerror( RC rc, ISession& sess, CompilationError& ce, 
											 char*& res, size_t& len ) {
						if ( rc == RC_SYNTAX && ce.msg ) {
								if ( !res ) {
										len = ce.pos+strlen(ce.msg)+50;
										res = (char*)sess.malloc( len+1 );
								}
								len = snprintf( res, len, "%*s\nSyntax: %s at %d, line %d\n", 
																ce.pos+2, "^", ce.msg, ce.pos, ce.line );
						} else if ( rc != RC_OK ) {
								if ( !res ) {
										len = 50; res = (char*)sess.malloc( len+1 );
								}
								len = snprintf( res, len, "affinity error: (%d)\n", rc );
						}
				}
#endif
		};
		static void reportPIN(ISession & pSession, IPIN & pPIN)
		{
			std::ostringstream lOs;
			AfySerialization::ContextOutXml lXmlCtx(lOs, pSession);
			AfySerialization::OutXml::pin(lXmlCtx, pPIN);
			report(AfyRC::MSG_DEBUG, lOs.str().c_str());
		}
	protected:
		const URIMap * mProps;
	public:
		WebappService(URIMap *p) : mProps(p) {}
		virtual ~WebappService() {}
		virtual RC create(IServiceCtx *ctx,uint32_t& dscr,Processor *&ret)
		{
			switch (dscr&ISRV_PROC_MASK)
			{
				case ISRV_WRITE:
				case ISRV_READ:
					dscr|=ISRV_NOCACHE|ISRV_SERVER|ISRV_ALLOCBUF; // Note: we cache our parameters internally, and also don't want to think about cleanup between usage sessions.
					if ((ret=new(ctx) WebappServiceProc(*this, ctx))==NULL) return RC_NOMEM;
					break;
				default:
					return RC_INVOP;
			}
			return RC_OK;
		}
};

extern "C" AFY_EXP bool SERVICE_INIT(WEBAPP)(ISession *ses,const Value *,unsigned,bool fNew)
{
	IAffinity *ctx=ses->getAffinity();

	URIMap *pmap=(URIMap*)ctx->malloc(sizeof(sProps)/sizeof(sProps[0])*sizeof(URIMap)); if (pmap==NULL) return false;
	for (unsigned i=0; i<sizeof(sProps)/sizeof(sProps[0]); i++) {pmap[i].URI=sProps[i]; pmap[i].uid=STORE_INVALID_URIID;}
	if (ses->mapURIs(sizeof(sProps)/sizeof(sProps[0]),pmap)!=RC_OK) return false;

	if (fNew)
	{
		Value lVenum[4]; int iE = 0;
		lVenum[iE].set(pmap[kPIENUM_MODES].URI); lVenum[iE].setPropID(PROP_SPEC_OBJID); iE++;
		lVenum[iE].set("PIN"); lVenum[iE].setPropID(PROP_SPEC_ENUM); lVenum[iE].op = OP_ADD; lVenum[iE].eid = STORE_LAST_ELEMENT; iE++;
		lVenum[iE].set("FILE"); lVenum[iE].setPropID(PROP_SPEC_ENUM); lVenum[iE].op = OP_ADD; lVenum[iE].eid = STORE_LAST_ELEMENT; iE++;
		lVenum[iE].set("BURN"); lVenum[iE].setPropID(PROP_SPEC_ENUM); lVenum[iE].op = OP_ADD; lVenum[iE].eid = STORE_LAST_ELEMENT; iE++;
		RC lRC;
		if (RC_OK != (lRC = ses->createPIN(lVenum, iE, NULL, MODE_COPY_VALUES | MODE_PERSISTENT)) && RC_ALREADYEXISTS != lRC)
			report(AfyRC::MSG_WARNING, "Webapp: Failed to create MODES enum: RC=%d\n", lRC);
	}

	WebappService *was=new(ctx) WebappService(pmap);
	if (was==NULL || ctx->registerService(WEBAPPSERVICE_NAME,was)!=RC_OK) return false;
	return true;
}

/*
  SET TRACE ALL COMMUNICATIONS;
  CREATE LOADER srv:webapp AS 'webapp';
  CREATE LOADER srv:http AS 'http';
  CREATE LISTENER mywebapp ON 8090 AS {.srv:sockets, .srv:HTTPRequest, .srv:webapp, .srv:HTTPResponse, .srv:sockets} SET srv:"webapp/config/paths"={'/Volumes/untitled/server/src/www/'}; --, srv:"webapp/config/modes"=WEBAPPMODES#FILE;
  -- INSERT afy:objectID=.mywebapp, afy:address=8090, afy:listen={.srv:sockets, .srv:HTTPRequest, .srv:webapp, .srv:HTTPResponse, .srv:sockets}, srv:"webapp/config/paths"={'/media/truecrypt1/src/server/src/www/'}, srv:"webapp/config/modes"=WEBAPPMODES#FILE;
*/

// TODO: in PIN|FILE mode, search for pin first, if not there search for file
// TODO: in PIN|FILE|BURN mode, also auto-burn to pin if not a pin yet
  // probably want this as a one-shot, automatic scan mode (burn all files under mPaths)
// TODO: in FILE mode, produce the file under path, or error
// TODO: in PIN mode, produce the pin corresponding to that path
// TODO: share port 80 (or whichever) with the REST interface?
