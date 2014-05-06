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

Written by Mark Venguerov 2014

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

namespace AfyModbus
{

#define	MODBUS_DEFAULT_PORT				502

#define	MODBUS_SERVICE_NAME		AFFINITY_SERVICE_PREFIX "MODBUS"
#define	MODBUS_PROP_NAME		AFFINITY_SERVICE_PREFIX "MODBUS"

enum ModbusPropNames
{
	MODBUS_FUNCTION, MODBUS_ADDRESS, MODBUS_DATA, MODBUS_NOUT, MODBUS_MASK, MODBUS_WRITE_ADDR, MODBUS_UNIT, MODBUS_ERROR
};

const static char *propURIs[] =
{
	MODBUS_PROP_NAME "/function",
	MODBUS_PROP_NAME "/address",
	MODBUS_PROP_NAME "/data",
	MODBUS_PROP_NAME "/nout",
	MODBUS_PROP_NAME "/mask",
	MODBUS_PROP_NAME "/writeAddress",
	MODBUS_PROP_NAME "/unit",
	MODBUS_PROP_NAME "/error",
};

/**
 * MODBUS public function codes
 */
#define	MBFU_READ_COILS				0x01
#define	MBFU_READ_DISCRETE			0x02
#define	MBFU_WRITE_COIL				0x05
#define	MBFU_WRITE_MULT_COILS		0x0F
#define	MBFU_READ_INPUT_REG			0x04
#define	MBFU_READ_HOLD_REG			0x03
#define	MBFU_WRITE_REG				0x06
#define	MBFU_WRITE_MULT_REGS		0x10
#define	MBFU_RW_MULT_REGS			0x17
#define	MBFU_MASK_WRITE_REG			0x16
#define	MBFU_READ_FIFO_QUEUE		0x18
#define	MBFU_READ_FILE_REC			0x14
#define	MBFU_WRITE_FILE_REC			0x15
#define	MBFU_READ_EXC_STATUS		0x07
#define	MBFU_DIAGNOSTIC				0x08
#define	MBFU_GET_COM_EVENT_CNT		0x0B
#define	MBFU_GET_COM_EVENT_LOG		0x0C
#define	MBFU_REPORT_SERVER_ID		0x11
#define	MBFU_READ_DEVICE_ID			0x2B

const static KWInit strFunctions[] =
{
	{"READ_COILS",			MBFU_READ_COILS},
	{"READ_DISCRETE",		MBFU_READ_DISCRETE},
	{"WRITE_COIL",			MBFU_WRITE_COIL},
	{"WRITE_MULT_COILS",	MBFU_WRITE_MULT_COILS},
	{"READ_INPUT_REG",		MBFU_READ_INPUT_REG},
	{"READ_HOLD_REG",		MBFU_READ_HOLD_REG},
	{"WRITE_REG",			MBFU_WRITE_REG},
	{"WRITE_MULT_REGS",		MBFU_WRITE_MULT_REGS},
	{"RW_MULT_REGS",		MBFU_RW_MULT_REGS},
	{"MASK_WRITE_REG",		MBFU_MASK_WRITE_REG},
	{"READ_FIFO_QUEUE",		MBFU_READ_FIFO_QUEUE},
	{"READ_FILE_REC",		MBFU_READ_FILE_REC},
	{"WRITE_FILE_REC",		MBFU_WRITE_FILE_REC},
	{"READ_EXC_STATUS",		MBFU_READ_EXC_STATUS},
	{"DIAGNOSTIC",			MBFU_DIAGNOSTIC},
	{"GET_COM_EVENT_CNT",	MBFU_GET_COM_EVENT_CNT},
	{"GET_COM_EVENT_LOG",	MBFU_GET_COM_EVENT_LOG},
	{"REPORT_SERVER_ID",	MBFU_REPORT_SERVER_ID},
	{"READ_DEVICE_ID",		MBFU_READ_DEVICE_ID},
};

struct MBAP
{
	uint16_t	txID;
	uint16_t	protocolID;
	uint16_t	length;
};

#define	MBAP_LENGTH				6
#define	MBAP_PROTOCOL_ID		0

#define MODBUS_DEFAULT_BUFSIZE	300

/* Table of CRC values for high–order byte */
const static unsigned char auchCRCHi[] = {
0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81,
0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01,
0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81,
0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01,
0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81,
0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01,
0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81,
0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01,
0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81,
0x40
};

/* Table of CRC values for low–order byte */
const static unsigned char auchCRCLo[] = {
0x00, 0xC0, 0xC1, 0x01, 0xC3, 0x03, 0x02, 0xC2, 0xC6, 0x06, 0x07, 0xC7, 0x05, 0xC5, 0xC4,
0x04, 0xCC, 0x0C, 0x0D, 0xCD, 0x0F, 0xCF, 0xCE, 0x0E, 0x0A, 0xCA, 0xCB, 0x0B, 0xC9, 0x09,
0x08, 0xC8, 0xD8, 0x18, 0x19, 0xD9, 0x1B, 0xDB, 0xDA, 0x1A, 0x1E, 0xDE, 0xDF, 0x1F, 0xDD,
0x1D, 0x1C, 0xDC, 0x14, 0xD4, 0xD5, 0x15, 0xD7, 0x17, 0x16, 0xD6, 0xD2, 0x12, 0x13, 0xD3,
0x11, 0xD1, 0xD0, 0x10, 0xF0, 0x30, 0x31, 0xF1, 0x33, 0xF3, 0xF2, 0x32, 0x36, 0xF6, 0xF7,
0x37, 0xF5, 0x35, 0x34, 0xF4, 0x3C, 0xFC, 0xFD, 0x3D, 0xFF, 0x3F, 0x3E, 0xFE, 0xFA, 0x3A,
0x3B, 0xFB, 0x39, 0xF9, 0xF8, 0x38, 0x28, 0xE8, 0xE9, 0x29, 0xEB, 0x2B, 0x2A, 0xEA, 0xEE,
0x2E, 0x2F, 0xEF, 0x2D, 0xED, 0xEC, 0x2C, 0xE4, 0x24, 0x25, 0xE5, 0x27, 0xE7, 0xE6, 0x26,
0x22, 0xE2, 0xE3, 0x23, 0xE1, 0x21, 0x20, 0xE0, 0xA0, 0x60, 0x61, 0xA1, 0x63, 0xA3, 0xA2,
0x62, 0x66, 0xA6, 0xA7, 0x67, 0xA5, 0x65, 0x64, 0xA4, 0x6C, 0xAC, 0xAD, 0x6D, 0xAF, 0x6F,
0x6E, 0xAE, 0xAA, 0x6A, 0x6B, 0xAB, 0x69, 0xA9, 0xA8, 0x68, 0x78, 0xB8, 0xB9, 0x79, 0xBB,
0x7B, 0x7A, 0xBA, 0xBE, 0x7E, 0x7F, 0xBF, 0x7D, 0xBD, 0xBC, 0x7C, 0xB4, 0x74, 0x75, 0xB5,
0x77, 0xB7, 0xB6, 0x76, 0x72, 0xB2, 0xB3, 0x73, 0xB1, 0x71, 0x70, 0xB0, 0x50, 0x90, 0x91,
0x51, 0x93, 0x53, 0x52, 0x92, 0x96, 0x56, 0x57, 0x97, 0x55, 0x95, 0x94, 0x54, 0x9C, 0x5C,
0x5D, 0x9D, 0x5F, 0x9F, 0x9E, 0x5E, 0x5A, 0x9A, 0x9B, 0x5B, 0x99, 0x59, 0x58, 0x98, 0x88,
0x48, 0x49, 0x89, 0x4B, 0x8B, 0x8A, 0x4A, 0x4E, 0x8E, 0x8F, 0x4F, 0x8D, 0x4D, 0x4C, 0x8C,
0x44, 0x84, 0x85, 0x45, 0x87, 0x47, 0x46, 0x86, 0x82, 0x42, 0x43, 0x83, 0x41, 0x81, 0x80,
0x40
};

static unsigned short CRC16(const uint8_t *puchMsg, unsigned short usDataLen)
{
	unsigned char uchCRCHi = 0xFF;		// high byte of CRC initialized
	unsigned char uchCRCLo = 0xFF;		// low byte of CRC initialized
	while (usDataLen--)					// pass through message buffer
	{
		unsigned uIndex = uchCRCLo ^ *puchMsg++;	// calculate the CRC
		uchCRCLo = uchCRCHi ^ auchCRCHi[uIndex];
		uchCRCHi = auchCRCLo[uIndex];
	}
	return (unsigned short)uchCRCHi << 8 | uchCRCLo;
}

class Modbus : public IService
{
	friend class ModbusParse;
	class ModbusParse : public IService::Processor {
		Modbus&	mgr;
	public:
		ModbusParse(Modbus& mq) : mgr(mq) {}
		RC invoke(IServiceCtx *ctx,const Value& inp,Value& out,unsigned& mode) {
			if ((mode&ISRV_PROC_MASK)!=ISRV_READ) return RC_INVPARAM;
			if (inp.isEmpty()||inp.length==0) {mode|=ISRV_EOM; return RC_OK;}
			if (!isString((ValueType)inp.type)) return RC_INVPARAM;
			const uint8_t *ptr=inp.bstr,*end=ptr+inp.length; uint8_t unit;
			if (ctx->getEndpointID()==SERVICE_SOCKETS) {
				if (inp.length<MBAP_LENGTH+2) {mode|=ISRV_NEEDMORE|ISRV_APPEND; return RC_OK;}
				const MBAP *pmb=(MBAP*)ptr; ptr+=MBAP_LENGTH; unit=*ptr++;
				if (swap16(pmb->protocolID)!=MBAP_PROTOCOL_ID) return RC_CORRUPTED;
				uint16_t len=swap16(pmb->length);
				if (uint32_t(len+MBAP_LENGTH)>inp.length) {mode|=ISRV_NEEDMORE|ISRV_APPEND; return RC_OK;}
				// set read mode from length
				const Value *pv; uint32_t txID=(uint32_t)swap16(pmb->txID)|(uint32_t)unit<<16;
				if ((mode&ISRV_REQUEST)!=0 || (pv=ctx->getParameter(PROP_SPEC_TOKEN))==NULL) {
					Value tx; tx.set(txID); tx.setPropID(PROP_SPEC_TOKEN);
					RC rc=ctx->getCtxPIN()->modify(&tx,1); if (rc!=RC_OK) return rc;
				} else if (pv->type!=VT_UINT || pv->ui!=txID) return RC_CORRUPTED;			// ??? mismatched transaction ID
			} else {
				if (inp.length<=3) return RC_CORRUPTED;
				unit=*ptr++; uint16_t crc=end[-1]<<8|end[-2]; end-=2;
				if (CRC16(ptr,(unsigned short)(end-ptr))!=crc) return RC_CORRUPTED;
			}
			IResAlloc *ra=ctx->getResAlloc(); assert(ra!=NULL); Value vals[5],rng[2],rng2[2],*pv=vals; uint32_t nvals=1; RC rc;
			// set unit property
			const unsigned func=*ptr++; vals[0].setEnum(mgr.props[MODBUS_FUNCTION].uid,(ElementID)(func&0x7F)); vals[0].setPropID(mgr.props[MODBUS_FUNCTION].uid);
			if ((func&0x80)!=0) {
				if ((mode&ISRV_RESPONSE)==0||ptr+1!=end) return RC_CORRUPTED;
				vals[1].set((unsigned)*ptr); vals[1].setPropID(mgr.props[MODBUS_ERROR].uid); nvals++;
#if 0
				RC rc=RC_OTHER;
				switch (*ptr) {
				case 1: rc=RC_INVOP; break;
				case 2: rc=RC_NOTFOUND; break;
				case 3: rc=RC_INVPARAM; break;
				case 4: rc=RC_OTHER; break;
				case 5: rc=RC_REPEAT; break;
				case 6: rc=RC_OTHER; break;		// server busy ???
				}
				//???
#endif
			} else switch (func) {
			default: return RC_CORRUPTED;
			case MBFU_READ_COILS:
			case MBFU_READ_DISCRETE:
			case MBFU_READ_HOLD_REG:
			case MBFU_READ_INPUT_REG:
				if ((mode&ISRV_REQUEST)!=0) {
					if (end-ptr<4) {mode|=ISRV_NEEDMORE|ISRV_APPEND; return RC_OK;}
					if ((rc=readAddr(ptr,&vals[nvals++],rng,func>=MBFU_READ_HOLD_REG))!=RC_OK) return rc;
				} else {
					if (ptr>=end || ptr+*ptr>=end) {mode|=ISRV_NEEDMORE|ISRV_APPEND; return RC_OK;}
					if ((rc=readData(ptr,pv,nvals,ra,func>MBFU_READ_DISCRETE))!=RC_OK) return rc;
				}
				break;
			case MBFU_WRITE_COIL:
			case MBFU_WRITE_REG:
				if (end-ptr<4) {mode|=ISRV_NEEDMORE|ISRV_APPEND; return RC_OK;}
				vals[nvals].set((unsigned)(ptr[0]<<8|ptr[1])+1);
				vals[nvals].setPropID(mgr.props[MODBUS_ADDRESS].uid); nvals++;
				if (func==MBFU_WRITE_REG) vals[nvals].set((unsigned)(ptr[2]<<8|ptr[3]));
				else if (ptr[2]!=0&&ptr[2]!=0xFF || ptr[3]!=0) return RC_INVPARAM;
				else vals[nvals].set(ptr[2]==0xFF);
				vals[nvals].setPropID(mgr.props[MODBUS_DATA].uid); nvals++;
				break;
			case MBFU_READ_EXC_STATUS:
			case MBFU_DIAGNOSTIC:
			case MBFU_GET_COM_EVENT_CNT:
			case MBFU_GET_COM_EVENT_LOG:
				return RC_INTERNAL;
			case MBFU_WRITE_MULT_COILS:
			case MBFU_WRITE_MULT_REGS:
				if (end-ptr<4) {mode|=ISRV_NEEDMORE|ISRV_APPEND; return RC_OK;}
				if ((rc=readAddr(ptr,&vals[nvals++],rng,func==MBFU_WRITE_MULT_REGS))!=RC_OK) return rc;
				if ((mode&ISRV_REQUEST)!=0) {
					if (ptr>=end || ptr+*ptr>=end) {mode|=ISRV_NEEDMORE|ISRV_APPEND; return RC_OK;}
					if ((rc=readData(ptr,pv,nvals,ra,func==MBFU_WRITE_MULT_REGS))!=RC_OK) return rc;
				}
				break;
			case MBFU_REPORT_SERVER_ID:
			case MBFU_READ_FILE_REC:
			case MBFU_WRITE_FILE_REC:
				return RC_INTERNAL;
			case MBFU_MASK_WRITE_REG:
				if (end-ptr<6) {mode|=ISRV_NEEDMORE|ISRV_APPEND; return RC_OK;}
				vals[nvals].set((unsigned)(ptr[0]<<8|ptr[1])+1);
				vals[nvals].setPropID(mgr.props[MODBUS_ADDRESS].uid); nvals++;
				if ((ptr[2]|ptr[3])!=0) {
					vals[nvals].set((unsigned)(ptr[2]<<8|ptr[3])+1);
					vals[nvals].setPropID(mgr.props[MODBUS_MASK].uid); nvals++;
				}
				vals[nvals].set((unsigned)(ptr[4]<<8|ptr[5])+1);
				vals[nvals].setPropID(mgr.props[MODBUS_DATA].uid); nvals++;
				break;
			case MBFU_RW_MULT_REGS:
				if ((mode&ISRV_REQUEST)!=0) {
					if (end-ptr<8) {mode|=ISRV_NEEDMORE|ISRV_APPEND; return RC_OK;}
					if ((rc=readAddr(ptr,&vals[nvals++],rng,true))!=RC_OK) return rc;
					if ((rc=readAddr(ptr+4,&vals[nvals],rng2,true))!=RC_OK) return rc;
					vals[nvals++].setPropID(mgr.props[MODBUS_WRITE_ADDR].uid); ptr+=8;
				}
				if (ptr>=end || ptr+*ptr>=end) {mode|=ISRV_NEEDMORE|ISRV_APPEND; return RC_OK;}
				if ((rc=readData(ptr,pv,nvals,ra,true))!=RC_OK) return rc;
				break;
			case MBFU_READ_FIFO_QUEUE:
			case MBFU_READ_DEVICE_ID:
				return RC_INTERNAL;
			}
			mode|=ISRV_EOM; return ra->createPIN(out,pv,nvals,NULL,pv==vals?MODE_COPY_VALUES:0);
		}
		RC readAddr(const uint8_t *ptr,Value *pv,Value rng[2],bool fReg) {
			uint16_t start=(ptr[0]<<8|ptr[1])+1,n=ptr[2]<<8|ptr[3];
			if (n==1) pv->set((unsigned)start);
			else if (n>0x7D0 || fReg && n>0x7D) return RC_INVPARAM;
			else {rng[0].set((unsigned)start); rng[1].set((unsigned)start+n); pv->setRange(rng);}
			pv->setPropID(mgr.props[MODBUS_ADDRESS].uid); return RC_OK;
		}
		RC readData(const uint8_t *ptr,Value *&pv,uint32_t& nvals,IResAlloc *ra,bool fReg) {
			if (!fReg) pv[nvals].set(ptr+1,*ptr);
			else if (*ptr==2) pv[nvals].set((unsigned)(ptr[1]<<8|ptr[2]));
			else if ((*ptr&1)!=0) return RC_CORRUPTED;
			else {
				const unsigned nData=*ptr++/2;
				uint32_t *data=(uint32_t*)ra->malloc(nData*sizeof(uint32_t)); if (data==NULL) return RC_NOMEM;
				for (unsigned i=0; i<nData; i++) {data[i]=ptr[0]<<8|ptr[1]; ptr+=2;}
				Value *nv=ra->createValues(nvals+1); if (nv==NULL) {ra->free(data); return RC_NOMEM;}
				for (unsigned i=0; i<nvals; i++) if ((nv[i]=pv[i]).type==VT_RANGE) {
					Value *nr=ra->createValues(2); if (nr==NULL) {ra->free(nv); ra->free(data); return RC_NOMEM;}
					memcpy(nr,pv[i].varray,2*sizeof(Value*)); nv[i].varray=nr;
				}
				pv=nv; pv[nvals].setArray(data,nData,(uint16_t)nData,1,VT_UINT);
			}
			pv[nvals++].setPropID(mgr.props[MODBUS_DATA].uid); return RC_OK;
		}
	};
	friend class ModbusRender;
	class ModbusRender : public IService::Processor {
		Modbus&	mgr;
	public:
		ModbusRender(Modbus& mq) : mgr(mq) {}
		RC invoke(IServiceCtx *ctx,const Value& inp,Value& out,unsigned& mode) {
			if ((mode&ISRV_PROC_MASK)!=ISRV_WRITE || !isString((ValueType)out.type) || out.str==NULL || out.length<MODBUS_DEFAULT_BUFSIZE) return RC_INVPARAM;
			unsigned func,i; MBAP *pmb=NULL; uint8_t *ptr=(uint8_t*)out.bstr,*end=ptr+out.length; RC rc;
			if (ctx->getEndpointID()==SERVICE_SOCKETS) {pmb=(MBAP*)ptr; ptr+=MBAP_LENGTH;} 
			const Value *pv=get(mgr.props[MODBUS_UNIT].uid,inp,ctx);
			uint8_t unitID=pv!=NULL && (pv->type==VT_UINT||pv->type==VT_INT&&pv->i>=0)?(uint8_t)pv->ui:0; *ptr++=unitID;
			if ((pv=get(mgr.props[MODBUS_FUNCTION].uid,inp,ctx))==NULL) return RC_TYPE;
			switch (pv->type) {
			default: return RC_TYPE;
			case VT_INT: if (pv->i<0) return RC_INVPARAM;
			case VT_UINT: func=pv->ui; break;
			case VT_ENUM:
				if (pv->enu.enumid!=mgr.props[MODBUS_FUNCTION].uid) return RC_TYPE;
				func=pv->enu.eltid; break;
			}
			if ((mode&ISRV_ERROR)!=0) func|=0x80; *ptr++=uint8_t(func);
			const Value *pa=get(mgr.props[MODBUS_ADDRESS].uid,inp,ctx);
			if ((func&0x80)!=0) {
				if ((mode&ISRV_RESPONSE)==0) return RC_INVOP;
				if ((pv=get(mgr.props[MODBUS_ERROR].uid,inp,ctx))==NULL||pa->type!=VT_UINT) return RC_TYPE;
				if (pa->ui==0||pa->ui>4) return RC_INVPARAM; *ptr++=uint8_t(pa->ui);
			} else switch (func) {
			default: return RC_INVOP;
			case MBFU_READ_COILS:
			case MBFU_READ_DISCRETE:
			case MBFU_READ_HOLD_REG:
			case MBFU_READ_INPUT_REG:
				if ((rc=(mode&ISRV_RESPONSE)!=0?writeMultiple(ctx,inp,func,ptr,false):writeAddr(pa,func,ptr,false))!=RC_OK) return rc;
				break;
			case MBFU_WRITE_COIL:
			case MBFU_WRITE_REG:
				if ((rc=writeAddr(pa,func,ptr))!=RC_OK) return rc;
				if ((pv=get(mgr.props[MODBUS_DATA].uid,inp,ctx))==NULL) return RC_TYPE;
				switch (pv->type) {
				case VT_BOOL: if (func!=MBFU_WRITE_COIL) return RC_TYPE;
					*ptr++=pv->b?0xFF:0x00; *ptr++=0; break;
				case VT_INT: if (pv->i<0) return RC_INVPARAM;
				case VT_UINT: if (pv->ui>=0x10000) return RC_INVPARAM;
					*ptr++=func==MBFU_WRITE_REG?uint8_t(pv->ui>>8):pv->ui!=0?0xFF:0x00;
					*ptr++=func==MBFU_WRITE_REG?uint8_t(pv->ui):0; break;
				}
				break;
			case MBFU_READ_EXC_STATUS:
				if ((mode&ISRV_RESPONSE)!=0) {
					if ((pv=get(mgr.props[MODBUS_DATA].uid,inp,ctx))==NULL||pv->type!=VT_UINT) return RC_TYPE;
					*ptr++=uint8_t(pv->ui);
				}
				break;
			case MBFU_DIAGNOSTIC:
				if (pmb!=NULL) return RC_INVOP;		// only for serial line
				return RC_INTERNAL;
			case MBFU_GET_COM_EVENT_CNT:
				if ((mode&ISRV_RESPONSE)!=0) {
					//???
				}
				return RC_INTERNAL;
			case MBFU_GET_COM_EVENT_LOG:
				if (pmb!=NULL) return RC_INVOP;		// only for serial line
				if ((mode&ISRV_RESPONSE)!=0) {
					//???
				}
				return RC_INTERNAL;
			case MBFU_WRITE_MULT_COILS:
			case MBFU_WRITE_MULT_REGS:
				if ((rc=writeAddr(pa,func,ptr))!=RC_OK) return rc;
				if ((mode&ISRV_RESPONSE)!=0) {
					if ((pv=get(mgr.props[MODBUS_NOUT].uid,inp,ctx))==NULL || pv->type!=VT_UINT&&(pv->type!=VT_INT||pv->i<0)) return RC_TYPE;
					if (pv->ui>(uint32_t)(func==MBFU_WRITE_MULT_COILS?0x7B0:0x7B)) return RC_INVPARAM;
					*ptr++=uint8_t(pv->ui>>8); *ptr++=uint8_t(pv->ui);
				} else if ((rc=writeMultiple(ctx,inp,func,ptr))!=RC_OK) return rc;
				break;
			case MBFU_REPORT_SERVER_ID:
				if (pmb!=NULL) return RC_INVOP;		// only for serial line
				if ((mode&ISRV_RESPONSE)!=0) {
					//???
				}
				return RC_INTERNAL;
			case MBFU_READ_FILE_REC:
			case MBFU_WRITE_FILE_REC:
				return RC_INTERNAL;
			case MBFU_MASK_WRITE_REG:
				if ((rc=writeAddr(pa,func,ptr))!=RC_OK) return rc; i=0;
				if ((pv=get(mgr.props[MODBUS_MASK].uid,inp,ctx))!=NULL) {
					if (pv->type!=VT_UINT && pv->type!=VT_INT) return RC_TYPE;
					if (pv->ui>=0x10000) return RC_INVPARAM; i=pv->ui;
				}
				*ptr++=uint8_t(i>>8); *ptr++=uint8_t(i);
				if ((pv=get(mgr.props[MODBUS_DATA].uid,inp,ctx))==NULL || pv->type!=VT_UINT && pv->type!=VT_INT) return RC_TYPE;
				if (pv->ui>=0x10000) return RC_INVPARAM; *ptr++=uint8_t(pv->ui>>8); *ptr++=uint8_t(pv->ui);
				break;
			case MBFU_RW_MULT_REGS:
				if ((mode&ISRV_REQUEST)!=0) {
					if ((rc=writeAddr(pa,func,ptr,false))!=RC_OK) return rc;
					if ((pa=get(mgr.props[MODBUS_WRITE_ADDR].uid,inp,ctx))==NULL) return RC_TYPE;
					if ((rc=writeAddr(pa,func,ptr))!=RC_OK || (rc=writeMultiple(ctx,inp,func,ptr))!=RC_OK) return rc;
				} else if ((rc=writeMultiple(ctx,inp,func,ptr,false))!=RC_OK) return rc;
				break;
			case MBFU_READ_FIFO_QUEUE:
			case MBFU_READ_DEVICE_ID:
				return RC_INTERNAL;
			}
			if (pmb!=NULL) {
				if ((mode&ISRV_REQUEST)!=0) {
					unsigned txID=uint16_t(++mgr.txID); pmb->txID=swap16(txID); txID|=(unsigned)unitID<<16;
					Value tx; tx.set(txID); tx.setPropID(PROP_SPEC_TOKEN);
					RC rc=ctx->getCtxPIN()->modify(&tx,1); if (rc!=RC_OK) return rc;
				} else {
					const Value *pv=ctx->getParameter(PROP_SPEC_TOKEN);
					unsigned txID=pv!=NULL&&pv->type==VT_UINT?pv->ui:0;
					pmb->txID=swap16((uint16_t)txID); *(uint8_t*)(pmb+1)=uint8_t(txID>>16);
				}
				pmb->protocolID=swap16(MBAP_PROTOCOL_ID);
				pmb->length=swap16(uint16_t(ptr-(uint8_t*)out.bstr-MBAP_LENGTH));
			} else {
				uint16_t crc=CRC16(out.bstr+1,(unsigned short)(ptr-(uint8_t*)out.bstr-1));
				*ptr++=uint8_t(crc); *ptr++=uint8_t(crc>>8);
			}
			out.length=ptr-(uint8_t*)out.bstr; mode|=ISRV_EOM; return RC_OK;
		}
		const Value *get(URIID uid,const Value& inp,IServiceCtx *ctx) const {
			const Value *pv=inp.type==VT_STRUCT?Value::find(uid,inp.varray,inp.length):inp.type==VT_REF?inp.pin->getValue(uid):NULL;
			return pv!=NULL?pv:ctx->getParameter(uid);
		}
		RC writeAddr(const Value *pa,unsigned func,uint8_t *&ptr,bool fSingle=true) const {
			uint16_t start,n;
			if (pa==NULL || pa->property!=mgr.props[MODBUS_ADDRESS].uid) return RC_TYPE;
			switch (pa->type) {
			default: return RC_TYPE;
			case VT_INT: if (pa->i<1) return RC_INVPARAM;
			case VT_UINT: if (pa->ui<1 || pa->ui>0x10000) return RC_INVPARAM;
				start=pa->ui-1; n=1; break;
			case VT_RANGE:
				if (fSingle) return RC_TYPE;
				switch (pa->varray[0].type) {
				default: return RC_TYPE;
				case VT_INT: if (pa->varray[0].i<1) return RC_INVPARAM;
				case VT_UINT: if (pa->varray[0].ui<1 || pa->varray[0].ui>0x10000) return RC_INVPARAM;
				}
				switch (pa->varray[1].type) {
				default: return RC_TYPE;
				case VT_INT: if (pa->varray[1].i<1) return RC_INVPARAM;
				case VT_UINT: if (pa->varray[1].ui<pa->varray[0].ui || pa->varray[1].ui>0x10000) return RC_INVPARAM;
				}
				start=pa->varray[0].ui-1; n=pa->varray[1].ui-pa->varray[0].ui+1;
				if (n>0x7D0 || func>=MBFU_READ_HOLD_REG && n>0x7D) return RC_INVPARAM;
				break;
			}
			*ptr++=uint8_t(start>>8); *ptr++=uint8_t(start); 
			if (!fSingle) {*ptr++=uint8_t(n>>8); *ptr++=uint8_t(n);}
			return RC_OK;
		}
		RC writeMultiple(IServiceCtx *ctx,const Value& inp,unsigned func,uint8_t *&ptr,bool fWrite=true) const {
			unsigned i; uint16_t nout;
			const Value *pv=get(mgr.props[MODBUS_DATA].uid,inp,ctx),*pn; if (pv==NULL) return RC_TYPE;
			switch (pv->type) {
			default: return RC_TYPE;
			case VT_UINT:
				//???
				break;
			case VT_BSTR:
				if (fWrite) {
					if (func!=MBFU_WRITE_MULT_COILS) return RC_TYPE; nout=pv->length*8;
					if ((pn=get(mgr.props[MODBUS_NOUT].uid,inp,ctx))!=NULL && (pn->type==VT_UINT || pn->type==VT_INT && pn->i>=0))
						{if (pn->ui<=0x7B0 && (pn->ui+7)/8<=pv->length) nout=(uint16_t)pn->ui; else return RC_TOOBIG;}
					*ptr++=uint8_t(nout>>8); *ptr++=uint8_t(nout); nout=(nout+7)/8;
				} else {
					if (func>MBFU_READ_DISCRETE) return RC_TYPE; if (pv->length>250) return RC_TOOBIG; nout=uint16_t(pv->length);
				}
				*ptr++=uint8_t(nout); memcpy(ptr,pv->bstr,nout); ptr+=nout; break;
			case VT_ARRAY:
				if (func<=MBFU_READ_DISCRETE||func==MBFU_WRITE_MULT_COILS||pv->fa.type!=VT_UINT&&pv->fa.type!=VT_INT) return RC_TYPE;
				if (pv->length>(uint32_t)(func==MBFU_RW_MULT_REGS?0x75:0x7B)) return RC_TOOBIG;
				if (fWrite) {*ptr++=0; *ptr++=uint8_t(pv->length);} *ptr++=uint8_t(pv->length*2);
				for (i=0; i<pv->length; i++) {uint16_t r=(uint16_t)pv->fa.ui[i]; *ptr++=uint8_t(r>>8); *ptr++=uint8_t(r);}
				break;
			case VT_COLLECTION:
				if (func<=MBFU_READ_DISCRETE||func==MBFU_WRITE_MULT_COILS||pv->isNav()) return RC_TYPE; 
				if (pv->length>(uint32_t)(func==MBFU_RW_MULT_REGS?0x75:0x7B)) return RC_TOOBIG;
				if (fWrite) {*ptr++=0; *ptr++=uint8_t(pv->length);} *ptr++=uint8_t(pv->length*2);
				for (i=0; i<pv->length; i++) {
					if (pv->varray[i].type!=VT_UINT && (pv->varray[i].type!=VT_INT||pv->varray[i].i<0)) return RC_TYPE;
					uint16_t r=(uint16_t)pv->varray[i].ui; *ptr++=uint8_t(r>>8); *ptr++=uint8_t(r);
				}
				break;
			}
			return RC_OK;
		}
	};
	const	URIMap	*const	props;
	SharedCounter			txID;
public:
	Modbus(URIMap *um,bool fRsp=false) : props(um) {}
	~Modbus() {}
	RC create(IServiceCtx *ctx,uint32_t& dscr,Processor *&ret) {
		switch (dscr&ISRV_PROC_MASK) {
		default: return RC_INVOP;
		case ISRV_READ:
			if ((ret=new(ctx) ModbusParse(*this))==NULL) return RC_NOMEM;
			break;
		case ISRV_WRITE:
			if ((ret=new(ctx) ModbusRender(*this))==NULL) return RC_NOMEM;
			dscr|=ISRV_ALLOCBUF|ISRV_ERROR; break;
		}
		ctx->setKeepalive(true);
		return RC_OK;
	}
	size_t getBufSize() const {
		return MODBUS_DEFAULT_BUFSIZE;
	}
	void getSocketDefaults(int& proto,uint16_t& port) const {
		proto=IPPROTO_TCP; port=MODBUS_DEFAULT_PORT;
	}
};

};

using namespace AfyModbus;

extern "C" AFY_EXP bool SERVICE_INIT(MODBUS)(ISession *ses,const Value *pars,unsigned nPars,bool fNew)
{
	IAffinity *ctx=ses->getAffinity();

	URIMap *pmap=(URIMap*)ctx->malloc(sizeof(propURIs)/sizeof(propURIs[0])*sizeof(URIMap)); if (pmap==NULL) return false;
	for (unsigned i=0; i<sizeof(propURIs)/sizeof(propURIs[0]); i++) {pmap[i].URI=propURIs[i]; pmap[i].uid=0;}
	if (ses->mapURIs(sizeof(propURIs)/sizeof(propURIs[0]),pmap)!=RC_OK) return false;

	void *p=ctx->malloc(sizeof(Modbus)); if (p==NULL) return false;
	if (ctx->registerService(MODBUS_SERVICE_NAME,new(p) Modbus(pmap))!=RC_OK) return false;

	ctx->registerPrefix("modbus",6,MODBUS_PROP_NAME "/",sizeof(MODBUS_PROP_NAME));
	if (fNew) {
		static const unsigned nElts=sizeof(strFunctions)/sizeof(strFunctions[0]); Value elts[nElts],props[2];
		for (unsigned i=0; i<nElts; i++) {elts[i].set(strFunctions[i].kw); elts[i].eid=strFunctions[i].val;}
		props[0].setURIID(pmap[MODBUS_FUNCTION].uid); props[0].setPropID(PROP_SPEC_OBJID);
		props[1].set(elts,nElts); props[1].setPropID(PROP_SPEC_ENUM);
		RC rc=ses->createPIN(props,2,NULL,MODE_COPY_VALUES|MODE_PERSISTENT|MODE_FORCE_EIDS);
		if (rc!=RC_OK && rc!=RC_ALREADYEXISTS) {
			report(MSG_ERROR,"MODBUS service: failed to register Functions enum (%d)\n",rc);
			// return false;
		}
	}
	return true;
}
