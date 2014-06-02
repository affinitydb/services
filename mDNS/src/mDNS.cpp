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

Written by Mark Venguerov 2013

**************************************************************************************/

#include <afysock.h>
#include <afyutils.h>
#include <startup.h>
#include <new>
#include <stdio.h>
#include <stdlib.h>

#if defined(WIN32) || defined(__APPLE__)
#include "dns_sd.h"
#else
#include <avahi-compat-libdns_sd/dns_sd.h>
#endif

using namespace Afy;

#define	MDNS_NAME			AFFINITY_SERVICE_PREFIX "mDNS"

#define	mDNS_ALL_SERVICES	"_services._dns-sd._udp"

#define	mDNS_AFF_TYPE		"_affinity"
#define	mDNS_TCP_PROTO		"_tcp"
#define	mDNS_UDP_PROTO		"_udp"

#define	AFF_KEY_TXT			"pubkey="

enum mDNSPropNames
{
	mDNS_REGTYPE, mDNS_SUBTYPE, mDNS_PROTOCOL, mDNS_DOMAIN, mDNS_SRVNAME, mDNS_HOST, mDNS_PORT, mDNS_TXTREC
};

const static char *propURIs[] =
{
	MDNS_NAME "/regtype",
	MDNS_NAME "/subtype",
	MDNS_NAME "/protocol",
	MDNS_NAME "/domain",
	MDNS_NAME "/serviceName",
	MDNS_NAME "/host",
	MDNS_NAME "/port",
	MDNS_NAME "/TXTRecord",
};

#define	MDRS_SDREF		0x0001
#define	MDRS_QUEUED		0x0002
#define	MDRS_ERROR		0x0004
#define	MDRS_SUSPENDED	0x0008

class mDNS;

struct SrvDscr
{
	char		*buf;
	size_t		type;
	size_t		domain;
	uint32_t	iidx;
	bool		fDelete;
};

class mDNSRes : public IAfySocket
{
protected:
	mDNSRes				*next;
	mDNS&				mgr;
	const		URIID	lid;
	DNSServiceRef		sdref;
	unsigned			state;
	ISession			*ses;
public:
	mDNSRes(mDNS& m,URIID id);
	DNSServiceRef	*getServiceRef() {return &sdref;}
	SOCKET			getSocket() const {return (SOCKET)DNSServiceRefSockFD(sdref);}
	void			process(ISession *ss,unsigned bits) {
		assert((state&(MDRS_SDREF|MDRS_QUEUED))==(MDRS_SDREF|MDRS_QUEUED));
		if ((bits&R_BIT)!=0) {
			ses=ss; DNSServiceErrorType err=DNSServiceProcessResult(sdref); ses=NULL;
			if (err!=kDNSServiceErr_NoError || (state&MDRS_ERROR)!=0) destroy();
		} else if ((bits&E_BIT)!=0) destroy();
	}
	IAffinity		*getAffinity() const;
	ISession		*getSession() const {return NULL;}
	void			setSDRef() {state|=MDRS_SDREF;}
	void			setError() {state|=MDRS_ERROR;}
	RC				queue();
	virtual	void	destroy();
	friend	class	mDNS;
};

class mDNSProc : public IService::Processor
{
	mDNS&				mgr;
	DynArray<SrvDscr>	dscrs;
	unsigned			idx;
	Value				pin;
	IServiceCtx			*ctx;
public:
	mDNSProc(mDNS& m,IMemAlloc *ma) : mgr(m),dscrs(ma),idx(0),ctx(NULL) {pin.setEmpty();}
	RC			invoke(IServiceCtx *ctx,const Value& inp,Value& out,unsigned& mode);
	void		cleanup(IServiceCtx *ctx,bool fDestroying);
	static void DNSSD_API mDNSResolveReply(DNSServiceRef sdref,DNSServiceFlags flags,uint32_t interfaceIndex,DNSServiceErrorType err,const char *fullname,const char *hosttarget,uint16_t port,uint16_t txtLen,const unsigned char *txtRecord,void *context);
	friend	class mDNSListener;
};

class mDNSListener : public mDNSRes, public IListener
{
	mDNSProc	*proc;
	Value		*vals;
	unsigned	nVals;
public:
	mDNSListener(mDNS& m,URIID id) : mDNSRes(m,id),proc(NULL),vals(NULL),nVals(0) {}
	IService	*getService() const;
	URIID		getID() const {return lid;}
	RC			create(IServiceCtx *ctx,uint32_t& dscr,IService::Processor *&ret);
	RC			stop(bool fSuspend);
	static void DNSSD_API mDNSBrowseReply(DNSServiceRef sdref,DNSServiceFlags flags,uint32_t interfaceIndex,DNSServiceErrorType err,const char *serviceName,const char *regtype,const char *replyDomain,void *context);
	friend	class	mDNS;
};

class mDNS : public IService, public IListenerNotification
{
	friend	class	mDNSListener;
	friend	class	mDNSProc;
	friend	class	mDNSRes;
	class mDNSProc : public IService::Processor {
		mDNS&		mgr;
	public:
		mDNSProc(mDNS& m) : mgr(m) {}
		RC invoke(IServiceCtx *ctx,const Value& inp,Value& out,unsigned& mode) {
			return RC_OK;
		}
	};
	IAffinity		*const ctx;
	const URIMap	*const props;
	URIID			sid;
	mDNSRes			*lstRes;
	uint16_t		lTXT;
	uint8_t			TXT[256];
public:
	mDNS(IAffinity *ct,URIMap *um) : ctx(ct),props(um),sid(STORE_INVALID_URIID),lstRes(NULL) {
		memcpy(TXT+1,AFF_KEY_TXT,sizeof(AFF_KEY_TXT)-1); lTXT=sizeof(AFF_KEY_TXT);
		size_t l=ctx->getPublicKey(TXT+lTXT,sizeof(TXT)-lTXT,false); lTXT+=(uint16_t)l; TXT[0]=(uint8_t)(lTXT-1);
	}
	~mDNS() {}
	void setUID(URIID s) {sid=s;}
	RC create(IServiceCtx *ctx,uint32_t& dscr,Processor *&ret) {
		switch (dscr&ISRV_PROC_MASK) {
		case ISRV_WRITE:
		case ISRV_READ:
			break;
		default:
			return RC_INVOP;
		}
		return RC_OK;
	}
	static void DNSSD_API mDNSRegisterReply(DNSServiceRef sdref,DNSServiceFlags flags,DNSServiceErrorType err, const char *name,const char *regtype,const char *domain,void *context) {
		mDNSRes *res=(mDNSRes*)context; if (err!=kDNSServiceErr_NoError) {report(MSG_ERROR,"mDNS registration failed: %d\n",err); res->setError();}
	}
#if defined(WIN32) || defined(__APPLE__)
	static void DNSSD_API mDNSGetAddrInfoReply(DNSServiceRef sdref,DNSServiceFlags flags,uint32_t interfaceIndex,DNSServiceErrorType err,const char *hostname,const struct sockaddr *saddr,uint32_t ttl,void *context) {
		SockAddr& ai=*(SockAddr*)context;
		if (err!=kDNSServiceErr_NoError) report(MSG_ERROR,"mDNSGetAddrInfo failed for host=%s(%d)\n",hostname,err);
		else if (saddr->sa_family==AF_INET) memcpy(&ai.saddr,saddr,ai.laddr=sizeof(sockaddr_in));
		else if (saddr->sa_family==AF_INET6) memcpy(&ai.saddr,saddr,ai.laddr=sizeof(sockaddr_in6));
		else report(MSG_ERROR,"Unsupported family in mDNSGetAddrInfo: %d, host=%s\n",saddr->sa_family,hostname);
	}
#endif
	RC getRegtype(char *regtype,ISession *ses,const Value *reg,const Value *sub,const Value *proto,const Value *addr,uint16_t *port=NULL) {
		bool fUDP=false; uint32_t lrt=0,l; size_t ll; RC rc;
		if (addr!=NULL) {
			SockAddr ai; if ((rc=ai.resolve(addr))!=RC_OK) return rc;
			if (ai.socktype==SOCK_DGRAM) fUDP=true;
			if (port!=NULL) {
				if (ai.saddr.ss_family==AF_INET) *port=((sockaddr_in*)&ai.saddr)->sin_port;
				else if (ai.saddr.ss_family==AF_INET6) *port=((sockaddr_in6*)&ai.saddr)->sin6_port;
			}
		}
		memcpy(regtype,mDNS_AFF_TYPE,sizeof(mDNS_AFF_TYPE)-1); lrt=sizeof(mDNS_AFF_TYPE)-1;
		if (reg!=NULL) switch (reg->type) {
		case VT_STRING: if (reg->length!=0) {lrt=min(reg->length,14u); memcpy(regtype,reg->str,lrt);}	break; // check no dots
		case VT_URIID: ll=14; if (ses->getURI(reg->uid,regtype,ll)==RC_OK) lrt=(uint32_t)ll; break;
		}
		regtype[lrt++]='.';
		if (fUDP) {memcpy(regtype+lrt,mDNS_UDP_PROTO,sizeof(mDNS_UDP_PROTO)); lrt+=sizeof(mDNS_UDP_PROTO)-1;}
		else {memcpy(regtype+lrt,mDNS_TCP_PROTO,sizeof(mDNS_TCP_PROTO)); lrt+=sizeof(mDNS_TCP_PROTO)-1;}
		if (sub!=NULL) switch (sub->type) {
		case VT_STRING:
			if (sub->length!=0) {regtype[lrt++]=','; l=min(reg->length,(uint32_t)(sizeof(regtype)-lrt-1)); memcpy(regtype+lrt,reg->str,l); regtype[lrt+l]=0;}
			break;
		case VT_URIID:
			regtype[lrt++]=','; ll=sizeof(regtype)-lrt-1; if ((rc=ses->getURI(reg->uid,regtype+lrt,ll))!=RC_OK) return rc; regtype[lrt+ll]=0; break;
		}
		return RC_OK;
	}
	RC onListener(ISession *ses,URIID sid,const Value *vals,unsigned nVals,const Value *srvInfo,unsigned nSrvInfo,bool fStop) {
		if (sid!=SERVICE_SOCKETS) return RC_OK; const Value *pv=Value::find(PROP_SPEC_OBJID,vals,nVals);
		if (fStop) {
			if (pv!=NULL && pv->type==VT_URIID)
				for (mDNSRes *md=lstRes; md!=NULL; md=md->next) if (md->lid==pv->uid) {md->destroy(); break;}
			return RC_OK;
		}
		URIID uid=props[mDNS_REGTYPE].uid; const Value *reg=Value::find(uid,vals,nVals); if (reg==NULL) reg=Value::find(uid,srvInfo,nSrvInfo);
		uid=props[mDNS_SUBTYPE].uid; const Value *sub=Value::find(uid,vals,nVals); if (sub==NULL) sub=Value::find(uid,srvInfo,nSrvInfo);
		if (reg!=NULL || sub!=NULL) {
			mDNSRes *res=new(ctx) mDNSRes(*this,pv!=NULL && pv->type==VT_URIID?pv->uid:STORE_INVALID_URIID); if (res==NULL) return RC_NOMEM;
			char srvname[64],regtype[128]; srvname[0]=0; size_t ll; uint16_t port=80; RC rc;
			uid=props[mDNS_PROTOCOL].uid; const Value *udp=Value::find(uid,vals,nVals); if (udp==NULL) udp=Value::find(uid,srvInfo,nSrvInfo);
			if ((pv=Value::find(PROP_SPEC_ADDRESS,vals,nVals))==NULL) pv=Value::find(PROP_SPEC_ADDRESS,srvInfo,nSrvInfo);
			if ((rc=getRegtype(regtype,ses,reg,sub,udp,pv,&port))!=RC_OK) return rc;
			ll=ses->getStoreIdentityName(srvname,sizeof(srvname)-1); srvname[ll]=0;
			if (memchr(srvname,'.',ll)!=NULL || memchr(srvname,'\\',ll)!=NULL) for (size_t i=0; i<ll; i++)
				if (srvname[i]=='.' || srvname[i]=='\\') {
					//...
				}
			uid=props[mDNS_DOMAIN].uid; const char *domain=NULL;
			if (((pv=Value::find(uid,vals,nVals))!=NULL || (pv=Value::find(uid,srvInfo,nSrvInfo))!=NULL) && pv->type==VT_STRING) domain=pv->str;
			DNSServiceErrorType err=DNSServiceRegister(res->getServiceRef(),0,0,srvname,regtype,domain,NULL,port,lTXT,TXT,mDNSRegisterReply,res);
			if (err==kDNSServiceErr_NoError) res->setSDRef(); else {report(MSG_ERROR,"DNSServiceRegister failed: %d\n",err); res->destroy(); return mDNSError(err);}
			if ((rc=res->queue())!=RC_OK) {res->destroy(); return rc;}
		}
		return RC_OK;
	}
	RC listen(ISession *ses,URIID id,const Value *vals,unsigned nVals,const Value *srvInfo,unsigned nSrvInfo,unsigned mode,IListener *&ret) {
		mDNSListener *lst=new(ctx) mDNSListener(*this,id); if (lst==NULL) return RC_NOMEM;
		if (vals!=NULL && nVals!=0) {RC rc=ses->copyValues(vals,lst->nVals=nVals,lst->vals); if (rc!=RC_OK) {lst->destroy(); return RC_NOMEM;}}
		char regtype[128]; RC rc; const Value *pv;
		URIID uid=props[mDNS_REGTYPE].uid; const Value *reg=Value::find(uid,vals,nVals); if (reg==NULL) reg=Value::find(uid,srvInfo,nSrvInfo);
		if (reg!=NULL && reg->type==VT_STRING && reg->length==1 && reg->str[0]=='*') memcpy(regtype,mDNS_ALL_SERVICES,sizeof(mDNS_ALL_SERVICES));
		else {
			uid=props[mDNS_SUBTYPE].uid; const Value *sub=Value::find(uid,vals,nVals); if (sub==NULL) sub=Value::find(uid,srvInfo,nSrvInfo);
			uid=props[mDNS_PROTOCOL].uid; const Value *udp=Value::find(uid,vals,nVals); if (udp==NULL) udp=Value::find(uid,srvInfo,nSrvInfo);
			if ((pv=Value::find(PROP_SPEC_ADDRESS,vals,nVals))==NULL) pv=Value::find(PROP_SPEC_ADDRESS,srvInfo,nSrvInfo);
			if ((rc=getRegtype(regtype,ses,reg,sub,udp,pv))!=RC_OK) return rc;
		}
		uid=props[mDNS_DOMAIN].uid; const char *domain=NULL;
		if (((pv=Value::find(uid,vals,nVals))!=NULL || (pv=Value::find(uid,srvInfo,nSrvInfo))!=NULL) && pv->type==VT_STRING) domain=pv->str;
		DNSServiceErrorType err=DNSServiceBrowse(lst->getServiceRef(),0,0,regtype,domain,mDNSListener::mDNSBrowseReply,lst);
		if (err==kDNSServiceErr_NoError) lst->setSDRef(); else {report(MSG_ERROR,"DNSServiceBrowse failed: %d\n",err); lst->destroy(); return mDNSError(err);}
		if ((rc=lst->queue())!=RC_OK) {lst->destroy(); return rc;}
		ret=lst; return RC_OK;
	}
	RC resolve(ISession *ses,const Value *vals,unsigned nVals,IAddress& res) {
		const Value *srv=Value::find(props[mDNS_SRVNAME].uid,vals,nVals); if (srv==NULL || srv->type!=VT_STRING) return RC_INVPARAM;
#if defined(WIN32) || defined(__APPLE__)
		DNSServiceRef sdRef; DNSServiceErrorType err=DNSServiceGetAddrInfo(&sdRef,0,0,0,srv->str,mDNSGetAddrInfoReply,&res);
		if (err!=kDNSServiceErr_NoError) {report(MSG_ERROR,"DNSServiceGetAddrInfo failed: %d\n",err); return mDNSError(err);}
		RC rc=RC_OK; if ((err=DNSServiceProcessResult(sdRef))!=kDNSServiceErr_NoError) {report(MSG_ERROR,"DNSServiceProcessResult in resolve() failed: %d\n",err); rc=mDNSError(err);}
		DNSServiceRefDeallocate(sdRef); return rc;
#else
		//???
		return RC_INTERNAL;
#endif
	}
	void shutdown() {
		for (mDNSRes *md=lstRes; md!=NULL; md=md->next) {
			if ((md->state&MDRS_QUEUED)!=0) ctx->unregisterSocket(md,true);
			if ((md->state&MDRS_SDREF)!=0) DNSServiceRefDeallocate(md->sdref);
		}
	}
	static RC mDNSError(DNSServiceErrorType err) {
		switch (err) {
		case kDNSServiceErr_NoSuchName:					return RC_NOTFOUND;
		case kDNSServiceErr_NoMemory:					return RC_NOMEM;
		case kDNSServiceErr_BadParam:
		case kDNSServiceErr_BadReference:
		case kDNSServiceErr_BadState:
		case kDNSServiceErr_BadFlags:					return RC_INVPARAM;
		case kDNSServiceErr_Unsupported:				return RC_INVOP;
		case kDNSServiceErr_NotInitialized:				return RC_CORRUPTED;
		case kDNSServiceErr_AlreadyRegistered:
		case kDNSServiceErr_NameConflict:				return RC_ALREADYEXISTS;
		//case kDNSServiceErr_Invalid:
		//case kDNSServiceErr_Firewall:
		//case kDNSServiceErr_Incompatible:
		//case kDNSServiceErr_BadInterfaceIndex:
		case kDNSServiceErr_Refused:					return RC_NOACCESS;
		case kDNSServiceErr_NoSuchRecord:				return RC_NOTFOUND;
		case kDNSServiceErr_NoAuth:						return RC_NOACCESS;
		case kDNSServiceErr_NoSuchKey:					return RC_NOTFOUND;
		//case kDNSServiceErr_NATTraversal:
		//case kDNSServiceErr_DoubleNAT:
		//case kDNSServiceErr_BadTime:
		//case kDNSServiceErr_BadSig:
		//case kDNSServiceErr_BadKey:
		//case kDNSServiceErr_Transient:
		//case kDNSServiceErr_ServiceNotRunning:
		//case kDNSServiceErr_NATPortMappingUnsupported:
		//case kDNSServiceErr_NATPortMappingDisabled:
		//case kDNSServiceErr_NoRouter:
		//case kDNSServiceErr_PollingMode:
		case kDNSServiceErr_Timeout:					return RC_TIMEOUT;
		}
		return RC_OTHER;
	}
};

mDNSRes::mDNSRes(mDNS& m,URIID id) 
	: next(m.lstRes),mgr(m),lid(id),state(0),ses(NULL)
{
	m.lstRes=this;
}

IAffinity *mDNSRes::getAffinity() const
{
	return mgr.ctx;
}

RC mDNSRes::queue()
{
	if ((state&MDRS_QUEUED)==0) {
		RC rc=mgr.ctx->registerSocket(this); if (rc!=RC_OK) return rc;
		state|=MDRS_QUEUED;
	}
	return RC_OK;
}

void mDNSRes::destroy()
{
	if ((state&MDRS_QUEUED)!=0) mgr.ctx->unregisterSocket(this,false);
	if ((state&MDRS_SDREF)!=0) DNSServiceRefDeallocate(sdref);
	for (mDNSRes **pp=&mgr.lstRes,*pr; (pr=*pp)!=NULL; pp=&pr->next)
		if (pr==this) {*pp=next; break;}
	mgr.ctx->free(this);
}

RC mDNSProc::invoke(IServiceCtx *sctx,const Value& inp,Value& out,unsigned& mode)
{
	if ((mode&ISRV_PROC_MODE)!=ISRV_READ) return RC_INVOP; if (idx>=dscrs) return RC_EOF;
	const SrvDscr& dscr=dscrs[idx]; DNSServiceRef sdRef; ctx=sctx;
	DNSServiceErrorType err=DNSServiceResolve(&sdRef,0,dscr.iidx,dscr.buf,dscr.buf+dscr.type,dscr.buf+dscr.domain,mDNSResolveReply,this);
	if (err!=kDNSServiceErr_NoError) {report(MSG_ERROR,"DNSServiceResolve failed: %d\n",err); return mDNS::mDNSError(err);}
	if ((err=DNSServiceProcessResult(sdRef))!=kDNSServiceErr_NoError) 
		{DNSServiceRefDeallocate(sdRef); report(MSG_ERROR,"DNSServiceProcessResult in invoke() failed: %d\n",err); return mDNS::mDNSError(err);}
	DNSServiceRefDeallocate(sdRef); idx++; out=pin; pin.setEmpty();	// dscr->fDelete ???
	return RC_OK;
}

void mDNSProc::cleanup(IServiceCtx *ctx,bool fDestroying)
{
	if (!fDestroying) {
		for (unsigned i=0; i<dscrs; i++) if (dscrs[i].buf!=NULL) dscrs.getmem()->free(dscrs[i].buf);
		dscrs.clear(); idx=0;
	}
}

IService *mDNSListener::getService() const
{
	return &mgr;
}

RC mDNSListener::create(IServiceCtx *ctx,uint32_t& dscr,IService::Processor *&ret)
{
	if ((dscr&ISRV_PROC_MASK)!=(ISRV_ENDPOINT|ISRV_READ)) return RC_INVOP; ret=proc; return RC_OK;
}

RC mDNSListener::stop(bool fSuspend)
{
	if (fSuspend) state|=MDRS_SUSPENDED;
	else {
		if ((state&MDRS_QUEUED)!=0) mgr.ctx->unregisterSocket(this,false);
		if ((state&MDRS_SDREF)!=0) DNSServiceRefDeallocate(sdref);
		state=0;
	}
	return RC_OK;
}

void DNSSD_API mDNSListener::mDNSBrowseReply(DNSServiceRef sdref,DNSServiceFlags flags,uint32_t interfaceIndex,DNSServiceErrorType err,const char *serviceName,const char *regtype,const char *replyDomain,void *context)
{
	if (err!=kDNSServiceErr_NoError) report(MSG_ERROR,"mDNS browse error %d\n",err);
	else {
		mDNSListener *lst=(mDNSListener*)context;
		//report(MSG_DEBUG,"mDNSBrowse: flags=%d, serviceName=%s, regtype=%s, replyDomain=%s\n",flags,serviceName,regtype,replyDomain);
		if (lst->ses!=NULL) {
			mDNSProc *prc=lst->proc; SrvDscr dscr;
			if (prc==NULL && (prc=lst->proc=new(lst->ses) mDNSProc(lst->mgr,lst->ses))==NULL) {report(MSG_ERROR,"mDNSBrowseReply: out of memory\n"); return;}
			size_t lname=serviceName!=NULL?strlen(serviceName):0,ltype=regtype!=NULL?strlen(regtype):0,ldomain=replyDomain!=NULL?strlen(replyDomain):0;
			if ((dscr.buf=(char*)lst->ses->malloc(lname+1+ltype+1+ldomain+1))==NULL) {report(MSG_ERROR,"mDNSBrowseReply: out of memory\n"); return;}
			memcpy(dscr.buf,serviceName,lname+1); memcpy(dscr.buf+lname+1,regtype,ltype+1); memcpy(dscr.buf+lname+1+ltype+1,replyDomain,ldomain+1);
			dscr.type=lname+1; dscr.domain=lname+1+ltype+1; dscr.iidx=interfaceIndex; dscr.fDelete=(flags&kDNSServiceFlagsAdd)==0;
			RC rc=prc->dscrs+=dscr; if (rc!=RC_OK) {report(MSG_ERROR,"mDNSBrowseReply: out of memory\n"); return;}
			if ((flags&kDNSServiceFlagsMoreComing)==0) {
				IServiceCtx *sctx=NULL; rc=lst->ses->createServiceCtx(lst->vals,lst->nVals,sctx,false,lst); lst->proc=NULL;
				if (rc!=RC_OK) {lst->proc->cleanup(NULL,true); report(MSG_ERROR,"mDNSBrowseReply: failed in ISession::createServiceCtx() (%d)\n",rc); return;}
				sctx->invoke(lst->vals,lst->nVals); sctx->destroy();
			}
		}
	}
}

void DNSSD_API mDNSProc::mDNSResolveReply(DNSServiceRef sdref,DNSServiceFlags flags,uint32_t interfaceIndex,DNSServiceErrorType err,const char *fullname,const char *hosttarget,uint16_t port,uint16_t txtLen,const unsigned char *txtRecord,void *context)
{
	if (err!=kDNSServiceErr_NoError) report(MSG_ERROR,"mDNS resolve error %d\n",err);
	else {
		mDNSProc *prc=(mDNSProc*)context;
		if (fullname!=NULL) {
			Value vals[6]; vals[0].setURIID(SERVICE_SOCKETS); vals[0].setPropID(PROP_SPEC_SERVICE);
			const SrvDscr *dscr=&prc->dscrs[prc->idx]; const char *type=dscr->buf+dscr->type;
			if (*type=='_') while (*++type!='\0') if (type[0]=='.') {if (type[1]=='_' && (type[2]=='u' || type[2]=='U')) vals[0].setMeta(META_PROP_ALT); break;}
			vals[1].setURIID(prc->mgr.sid); vals[1].setPropID(PROP_SPEC_RESOLVE);
			vals[2].set(fullname); vals[2].setPropID(prc->mgr.props[mDNS_SRVNAME].uid); unsigned i=3;
			if (hosttarget!=NULL) {vals[3].set(hosttarget); vals[3].setPropID(prc->mgr.props[mDNS_HOST].uid); i++;}
			vals[i].set((unsigned)ntohs(port)); vals[i].setPropID(prc->mgr.props[mDNS_PORT].uid); i++;
			if (txtLen!=0 && txtRecord!=NULL) {vals[i].set((uint8_t*)txtRecord,txtLen); vals[i].setPropID(prc->mgr.props[mDNS_TXTREC].uid); i++;}
			RC rc=prc->ctx->getResAlloc()->createPIN(prc->pin,vals,i,NULL,MODE_COPY_VALUES); 
			if (rc!=RC_OK) report(MSG_ERROR,"mDNS resolve: couldn't create PIN (%d)\n",rc);
		}
	}
}

extern "C" AFY_EXP bool SERVICE_INIT(mDNS)(ISession *ses,const Value *pars,unsigned nPars,bool fNew)
{
	IAffinity *ctx=ses->getAffinity();
	URIMap *pmap=(URIMap*)ctx->malloc(sizeof(propURIs)/sizeof(propURIs[0])*sizeof(URIMap)); if (pmap==NULL) return false;
	for (unsigned i=0; i<sizeof(propURIs)/sizeof(propURIs[0]); i++) {pmap[i].URI=propURIs[i]; pmap[i].uid=0;}
	if (ses->mapURIs(sizeof(propURIs)/sizeof(propURIs[0]),pmap)!=RC_OK) return false;

	mDNS *md=new(ctx) mDNS(ctx,pmap); URIID sid=STORE_INVALID_URIID;
	if (md==NULL || ctx->registerService(MDNS_NAME,md,&sid,md)!=RC_OK) return false;
	md->setUID(sid); assert(sid!=STORE_INVALID_URIID);
	ctx->registerPrefix("mdns",4,MDNS_NAME "/",sizeof(MDNS_NAME));
	
	if (fNew) {
		// register command enum
	}
	return true;
}
