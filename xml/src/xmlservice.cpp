/*
Copyright � 2004-2014 GoPivotal, Inc. All Rights Reserved.

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

#include <affinity.h>
#include <startup.h>
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <deque>
#include <algorithm>
#include <set>

#include "expat.h"
#include <assert.h>
#include "serialization.h"

#define XMLSERVICE_NAME AFFINITY_SERVICE_PREFIX "XML"

#define	MIME_XML	"application/xml"

#define TMPDBGENABLE 1
#if TMPDBGENABLE
	#define TMPDBG(stmts) {stmts;}
#else
	#define TMPDBG(stmts)
#endif

using namespace Afy;
typedef std::vector<Value> TValues;
typedef std::vector<TValues> TStack;
typedef std::deque<IPIN *> TPINsFIFO;
typedef std::set<std::string> TStringSet;

enum ePropIndex
{
	kPISTART = 0,
	kPIParameterRoots = kPISTART,
	kPIParameterQnPrefixes,
	kPINodeName,
	kPINodeValue,
	kPINodeParent, // Review: may or may not keep.
	kPINodeChildren,
	kPINodeAttributes,
	kPIComment,
	kPIInternalSymbolStacked,
	kPIInternalPinStacked,
	kPITOTAL
};

const static char *sProps[] =
{
	XMLSERVICE_NAME "/config/roots",
	XMLSERVICE_NAME "/config/output/qname/prefixes",
	XMLSERVICE_NAME "/node/name",
	XMLSERVICE_NAME "/node/value",
	XMLSERVICE_NAME "/node/parent", // Review: may or may not keep.
	XMLSERVICE_NAME "/node/children",
	XMLSERVICE_NAME "/node/attributes",
	XMLSERVICE_NAME "/comment",
	XMLSERVICE_NAME "/internal/symbol/stacked",
	XMLSERVICE_NAME "/internal/pin/stacked",
};

class XmlService : public IService
{
	protected:
		friend class XmlServiceProc;
		class XmlServiceProc : public IService::Processor
		{
			protected:
				// General.
				XmlService & mService; // Back-reference to the service.
				TStringSet mRootNames; // Configuration: which xml nodes should become PINs (as opposed to nested VT_STRUCT) (optional).
				bool mFirstInvoke; // Will be true the first time invoke is called, since last cleanup.
			protected:
				// Output.
				static char const * const sXMLTrailer;
				size_t const mXMLTrailerLen;
				std::string mCurOutput; // Any pending output not yet delivered.
				size_t mCurOutputPtr; // Pointer to the next character of mCurOutput to deliver.
				AfySerialization::ContextOutXml::TURIPrefix2QnamePrefix mQnPrefixes; // Preferred qname prefixes specified in configuration (optional).
			protected:
				// Input.
				struct Predicate_IsURIID // To easily find instances of a specific URIID in a set.
				{
					URIID mExpected;
					Predicate_IsURIID(URIID pExpected) : mExpected(pExpected) {}
					bool operator()(Value const & pV) const { return pV.property == mExpected; }
				};
				struct ParsingCtx // To provide context to the SAX parser ("user data").
				{
					XmlServiceProc * mThis; IServiceCtx * mServiceCtx;
					ParsingCtx(XmlServiceProc * pThis, IServiceCtx * pServiceCtx) : mThis(pThis), mServiceCtx(pServiceCtx) {}
				};
				TPINsFIFO mProduced; // PINs ready to be streamed out of the service.
				TStack mSAXStack; // A stack of vectors of values (some of which will become PINs, others will become VT_STRUCT, and yet others will first become symbols and then be transformed into actual values).
				XML_Parser mSAXParser; // SAX parser.
				ParsingCtx mSAXParsingCtx; // SAX parser's user data.
			public:
				XmlServiceProc(XmlService & pService, IServiceCtx * pCtx)
					: mService(pService)
					, mFirstInvoke(true)
					, mXMLTrailerLen(strlen(sXMLTrailer))
					, mCurOutputPtr(0)
					, mSAXParser(NULL)
					, mSAXParsingCtx(this, pCtx)
				{
					report(AfyRC::MSG_DEBUG, "Created a XmlServiceProc(%p)\n", this);
					readServiceConfig(pCtx); // Note: we can cache the service pin's parameters here, because we use ISRV_NOCACHE.
				}
				virtual ~XmlServiceProc() { report(AfyRC::MSG_DEBUG,"XmlServiceProc::~XmlServiceProc(%p)\n", this); }
				virtual RC invoke(IServiceCtx *ctx,const Value& inp,Value& out,unsigned& mode)
				{
					report(AfyRC::MSG_DEBUG, "XmlServiceProc::invoke(%p)\n", this);
					// TODO: comment about current state of ISRV_SPLIT, ISRV_NEEDFLUSH(in read?), ISRV_REFINP, etc.
					RC lRC = RC_OK;
					if (0 != (mode & ISRV_READ))
						lRC = doRead(ctx, inp, out, mode);
					else if (0 != (mode & ISRV_WRITE)) 
					{
						if (mFirstInvoke)
						{
							Value v; v.set(MIME_XML,sizeof(MIME_XML)-1); v.setPropID(PROP_SPEC_CONTENTTYPE);
							lRC = ctx->getCtxPIN()->modify(&v,1); if (RC_OK != lRC) return lRC;
						}
						lRC = doWrite(ctx, inp, out, mode);
					}
					mFirstInvoke = false;
					return lRC;
				}
				virtual void cleanup(IServiceCtx *ctx,bool fDestroy)
				{
					report(AfyRC::MSG_DEBUG, "XmlServiceProc::cleanup(%p)\n", this);

					// Destroy any non-consumed uncommitted PIN (input).
					for (TPINsFIFO::iterator iP = mProduced.begin(); mProduced.end() != iP; iP++)
						(*iP)->destroy();
					mProduced.clear();
					
					// Destroy any non-consumed parsed values on the stack (input).
					for (TStack::iterator iS = mSAXStack.begin(); mSAXStack.end() != iS; iS++)
					{
						for (TValues::iterator iV = (*iS).begin(); (*iS).end() != iV; iV++)
						{
							switch ((*iV).type)
							{
								case VT_STRING:
								case VT_STRUCT:
								case VT_COLLECTION:
									ctx->getSession()->freeValue(*iV);
									break;
								default:
									break;
							}
						}
					}
					mSAXStack.clear();

					// Free the SAX parser (simpler than XML_ParserReset, especially with ISRV_NOCACHE...).
					if (mSAXParser)
					{
						XML_ParserFree(mSAXParser);
						mSAXParser = NULL;
					}

					// Reset output-related stuff.
					mFirstInvoke = true;
					mCurOutput.clear();
					mCurOutputPtr = 0;
					mQnPrefixes.clear();
				}
			protected:
				RC doWrite(IServiceCtx *ctx,const Value& inp,Value& out,unsigned& mode)
				{
					RC lRC = RC_OK;

					// If we're not flushing yet, then we expect inp to represent the next pin to transform to xml...
					if (0 == (mode & ISRV_EOM))
					{
						if (inp.isEmpty())
							{ out.setEmpty(); return RC_OK; }
						else if (VT_REF != inp.type && VT_STRUCT != inp.type)
							{ report(AfyRC::MSG_DEBUG, "XmlServiceProc::invoke(%p): don't know how to serialize VT=%d\n", this, inp.type); return RC_INVPARAM; }

						// We may have some remains to produce from a previous iteration...
						char const * lToOutput = NULL;
						size_t lAvailable = 0;
						if (mCurOutput.length() > mCurOutputPtr)
						{
							// TODO: how does this work??? can we ignore inp?
							lToOutput = &mCurOutput.c_str()[mCurOutputPtr];
							lAvailable = mCurOutput.length() - mCurOutputPtr;
						}
						else
						{
							mCurOutput.clear();
							mCurOutputPtr = 0;
						}

						// We're ready to produce the next pin.
						std::ostringstream lOs;
						if (mFirstInvoke)
						{
							lOs << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" << std::endl;
							lOs << "<afyxml:result xmlns:afyxml=\"" AFFINITY_URI_PREFIX "xml/\" ";
							for (AfySerialization::ContextOutXml::TURIPrefix2QnamePrefix::const_iterator iPP = mQnPrefixes.begin(); mQnPrefixes.end() != iPP; iPP++)
								lOs << "xmlns:" << (*iPP).second << "=\"" << (*iPP).first << "\" ";
							lOs << ">" << std::endl;
						}

						AfySerialization::ContextOutXml lXmlCtx(lOs, *ctx->getSession(), AfySerialization::ContextOutXml::kFDefault, 1);
						lXmlCtx.setPreferredPrefixes(&mQnPrefixes);
						lXmlCtx.setImportConvention(&mService.mProps[kPINodeName]);
						if (VT_REF == inp.type)
							AfySerialization::OutXml::pin(lXmlCtx, *inp.pin);
						else
						{
							// Wrap in a temporary PIN (cheap solution for namespaces; may want to review, but
							// would imply putting namespaces in nodes other than PINs).
							Value lV = inp;
							IPIN * lTmpPIN = NULL;
							if (RC_OK == ctx->getSession()->createPIN(&lV, 1, &lTmpPIN) && lTmpPIN)
								{ AfySerialization::OutXml::pin(lXmlCtx, *lTmpPIN); lTmpPIN->destroy(); }
						}
						mCurOutput += lOs.str();
						lToOutput = mCurOutput.c_str();
						lAvailable = mCurOutput.length();

						if (RC_OK == lRC)
						{
							uint32_t lFillable = out.length; out.length = 0; // Note: This will remain 0 if lAvailable==0, i.e. if we have nothing more to produce.
							if (lAvailable)
							{
								uint32_t const lRemaining = std::min((uint32_t)lAvailable, lFillable);
								out.length = lRemaining; 
								memcpy((char *)out.str, lToOutput, lRemaining);
								mCurOutputPtr += lRemaining;
								lFillable -= lRemaining;
							}
							if (0 != out.length)
								mode |= ISRV_NEEDFLUSH; // IOW if we produced anything, tell the kernel that we'll have to flush at the end.
						}
					}
					else if (out.length >= mXMLTrailerLen) // When we're called for ISRV_NEEDFLUSH, finalize.
					{
						memcpy((char *)out.str, sXMLTrailer, mXMLTrailerLen);
						out.length = (uint32_t)mXMLTrailerLen;
						mode &= ~ISRV_NEEDFLUSH;
						lRC = RC_OK; // Review: would RC_EOF matter here? why or why not?
					}
					else
						lRC = RC_NOMEM;
					// TODO: finalize doWrite, taking into account latest notes from Mark.
					return lRC;
				}
			protected:
				RC doRead(IServiceCtx *ctx,const Value& inp,Value& out,unsigned& mode)
				{
					if (!out.isEmpty() || 0!=(mode&(ISRV_WRITE|ISRV_NEEDFLUSH))) return RC_INVPARAM;
					mode &= ~ISRV_NEEDMORE;
					if (0 == (mode & ISRV_MOREOUT) && inp.length > 0)
					{
						report(AfyRC::MSG_DEBUG, "XmlServiceProc::invoke(%p): received %d bytes\n", this, inp.length);
						#if 0
							report(AfyRC::MSG_DEBUG, "XmlServiceProc::invoke(%p): received %.100s [...]\n", this, (char *)inp.bstr);
						#endif

						// TODO:
						//   finish this (pass 1 / 0 depending on whether this is the last received chunk)
						//   -> can the kernel infra tell me this? or must I track my content (e.g. balancing root nodes)?
						haveSAXParser();
						XML_Parse(mSAXParser, (XML_Char*)inp.bstr, inp.length, 0);
						TMPDBG(for (TPINsFIFO::iterator iP = mProduced.begin(); mProduced.end() != iP; iP++) { reportPIN(*ctx->getSession(), *(*iP)); });
						report(AfyRC::MSG_DEBUG, "XmlServiceProc::invoke(%p): produced %d pins\n", this, mProduced.size());
					}
					RC lRC = RC_OK;
					if (0 == mProduced.size() && 0 == mSAXStack.size())
					{
						lRC = RC_EOF;
						if (mSAXParser)
							XML_Parse(mSAXParser, NULL, 0, 1);
						mode &= ~ISRV_MOREOUT;
					}
					else if (0 != mProduced.size())
					{
						// Note:
						//   Latest state is that this does produce the pins, but INSERT SELECT still fails at queryprc.cpp:315, even with a very simple xml file;
						//   I'm not sure if this is pure&simple unfinished stuff in the kernel, or if the xml structure contributes;
						//   those pins commit fine if I invoke commitPINs here.
						out.set(mProduced.front());
						out.op = OP_ADD;
						mProduced.pop_front();
						if (0 != mProduced.size())
							mode |= ISRV_MOREOUT;
						else
							mode &= ~ISRV_MOREOUT;
						lRC = RC_OK;
					}
					else if (0 != mSAXStack.size())
						mode |= ISRV_NEEDMORE;
					return lRC;
				}
				static void onStartElement_static(void * pUD, XML_Char const * pName, XML_Char const ** pAtts) { ((ParsingCtx *)pUD)->mThis->onStartElement(((ParsingCtx *)pUD)->mServiceCtx, pName, pAtts); }
				static void onCharacterData_static(void * pUD, XML_Char const * pStr, int pLen) { ((ParsingCtx *)pUD)->mThis->onCharacterData(((ParsingCtx *)pUD)->mServiceCtx, pStr, pLen); }
				static void onComment_static(void * pUD, XML_Char const * pComment) { ((ParsingCtx *)pUD)->mThis->onComment(((ParsingCtx *)pUD)->mServiceCtx, pComment); }
				static void onEndElement_static(void * pUD, XML_Char const * pName) { ((ParsingCtx *)pUD)->mThis->onEndElement(((ParsingCtx *)pUD)->mServiceCtx, pName); }
				static void onStartNamespaceDecl_static(void * pUD, XML_Char const * pPrefix, XML_Char const * pUri) { printf("*** xml prefix: %.100s uri: %.100s\n", pPrefix, pUri); } // TODO: Mark is ok with this but requested the ability to tightly scope (avoid "pollution", i.e. binding un-intended prefixes); all in all though, this is not urgent (usability feature).
			protected:
				void onStartElement(IServiceCtx * pCtx, XML_Char const * pName, XML_Char const ** pAtts)
				{
					URIID const lUid = lookupSymbol(*pCtx->getSession(), pName); // Note: All these names are destined to become URIIDs... considering the challenges imposed by expat (e.g. forced ns separator), and also the ability to avoid some allocations here, it seems better to resolve names to URIIDs straight away.
					TMPDBG(report(AfyRC::MSG_DEBUG, "-- started element %.200s (uid=%d)\n", pName, lUid));
					size_t lNumAttKV; for (lNumAttKV = 0; pAtts && pAtts[lNumAttKV]; lNumAttKV++){}
					TValues lVs((lNumAttKV > 0) ? 2 : 1);
					lVs[0].setURIID(lUid); 
					lVs[0].setPropID(mService.mProps[kPIInternalSymbolStacked].uid);
					if (lNumAttKV > 0)
					{
						// By default, store all attributes in a distinct VT_STRUCT.
						assert(0 == (lNumAttKV % 2));
						size_t const lNumV = lNumAttKV >> 1;
						Value * const lAttV = (Value *)pCtx->getSession()->malloc(lNumV * sizeof(Value));
						for (size_t iV = 0, iKV = 0; iV < lNumV; iV++, iKV++)
						{
							URIID const lAttUid = lookupSymbol(*pCtx->getSession(), pAtts[iKV++]);
							lAttV[iV].set(copyStr(*pCtx->getSession(), pAtts[iKV], (uint32_t)strlen(pAtts[iKV])));
							lAttV[iV].setPropID(lAttUid);
						}
						lVs[1].setStruct(lAttV, (uint32_t)lNumV);
						lVs[1].setPropID(mService.mProps[kPINodeAttributes].uid);
					}
					mSAXStack.push_back(lVs);
				}
				void onCharacterData(IServiceCtx * pCtx, XML_Char const * pStr, int pLen)
				{
					// Ignore empty text nodes.
					bool lEmpty = true;
					for (int iC = 0; iC < pLen && lEmpty; iC++)
						lEmpty = isspace(pStr[iC]);
					if (lEmpty)
						return;

					TMPDBG(std::string _lS = std::string(pStr, pLen); report(AfyRC::MSG_DEBUG, "-- processed text: %.200s\n", _lS.c_str()));

					// We'll bind the text value either to the innermost stacked symbol, or if there's none, as the 'value' of the innermost node being constructed.
					TValues & lStacked = mSAXStack.back();
					TValues::iterator iV = std::find_if(lStacked.begin(), lStacked.end(), Predicate_IsURIID(mService.mProps[kPIInternalSymbolStacked].uid));
					if (iV != lStacked.end())
					{
						// Convert the stacked symbol into an actual value of its parent.
						// Note: It remains on the stack until the end of the element, where it will be copied to its parent's list.
						URIID const lUid = (*iV).uid;
						TMPDBG(report(AfyRC::MSG_DEBUG, "--   converted symbol uid=%d into value\n", lUid));
						(*iV).set(copyStr(*pCtx->getSession(), pStr, pLen));
						(*iV).setPropID(lUid);
					}
					else
					{
						// Add to the parent a kPINodeValue.
						TMPDBG(report(AfyRC::MSG_DEBUG, "--   added as kPINodeValue\n"));
						Value lV;
						lV.set(copyStr(*pCtx->getSession(), pStr, pLen));
						lV.setPropID(mService.mProps[kPINodeValue].uid);
						lStacked.push_back(lV);
					}
				}
				void onComment(IServiceCtx * pCtx, XML_Char const * pComment)
				{
					if (0 == mSAXStack.size())
						return; // For now just ignore comments outside of any node.
					TValues & lStacked = mSAXStack.back();
					TMPDBG(report(AfyRC::MSG_DEBUG, "--   added a kPIComment\n"));
					Value lV;
					lV.set(copyStr(*pCtx->getSession(), pComment, (uint32_t)strlen(pComment)));
					lV.setPropID(mService.mProps[kPIComment].uid);
					lStacked.push_back(lV);
				}
				void onEndElement(IServiceCtx * pCtx, XML_Char const * pName)
				{
					// Get the stacked parent; make sure it's conform with current state.
					TMPDBG(report(AfyRC::MSG_DEBUG, "-- ending element %.200s\n", pName));
					TValues & lStacked = mSAXStack.back();
					TValues::iterator iUnhandledSym = lStacked.end();
					assert(lStacked.size() > 0);
					{
						// If the stacked parent contains a symbol not yet filled with a value, it should be this element.
						iUnhandledSym = std::find_if(lStacked.begin(), lStacked.end(), Predicate_IsURIID(mService.mProps[kPIInternalSymbolStacked].uid));
						if (lStacked.end() != iUnhandledSym)
						{
							assert(lookupSymbol(*pCtx->getSession(), pName) == (*iUnhandledSym).uid);
							TMPDBG(report(AfyRC::MSG_DEBUG, "--   found empty symbol for %.200s in parent; will name the parent accordingly\n", pName));
						}
						else
						{
							// If a stacked parent named pName already was assigned a value (e.g. during onCharacterData),
							// then simply finalize: pop the stack and add the value to its parent.
							URIID const lUid = lookupSymbol(*pCtx->getSession(), pName);
							TValues::const_iterator iTextVal = std::find_if(lStacked.begin(), lStacked.end(), Predicate_IsURIID(lUid));
							if (lStacked.end() != iTextVal)
							{
								TMPDBG(report(AfyRC::MSG_DEBUG, "--   found simple value for %.200s in parent\n", pName));
								Value lV;
								size_t const lNumValues = lStacked.size();
								if (1 == lNumValues)
									lV = (*iTextVal); // This is the plain case.
								else
								{
									// This more elaborate case will happen if the element had attributes; for the time being I chose to
									// represent this as a collection of {the_element_value, {attr1:attrval1, attr2:attrval2, ...}},
									// by default; maybe we'll prefer something else, or make parametrizable.
									Value * const lValues = (Value *)pCtx->getSession()->malloc(lNumValues * sizeof(Value));
									memcpy(lValues, &lStacked[0], lNumValues * sizeof(Value));
									lV.set(lValues, (uint32_t)lNumValues);
									lV.setPropID(lUid);
								}
								
								mSAXStack.pop_back();
								mSAXStack.back().push_back(lV);
								return;
							}
							TMPDBG(report(AfyRC::MSG_DEBUG, "***** could not find %.200s (%d) in lStacked\n", pName, lUid));
							TMPDBG(reportValues(*pCtx->getSession(), &lStacked[0], lStacked.size()));
							assert(false);
							return;
						}
					}

					// If this is an expected root, we're ready to create an uncommitted pin...
					TStringSet::const_iterator iRoot = mRootNames.find(pName);
					bool const lCreatePIN = (mRootNames.end() != iRoot || 1 == mSAXStack.size());

					// Deal with the pending unhandled symbol (there should be one).
					URIID const lPendingUid = (lStacked.end() != iUnhandledSym ? (*iUnhandledSym).uid : STORE_INVALID_URIID);
					if (lStacked.end() != iUnhandledSym)
					{
						// For a new PIN, convert it to the node's kPINodeName.
						if (lCreatePIN)
						{
							// Get a separator-free copy of pName...
							size_t lNameLen = 0;
							pCtx->getSession()->getURI((*iUnhandledSym).uid, NULL, lNameLen);
							char * lName = (char *)pCtx->getSession()->malloc(++lNameLen);
							pCtx->getSession()->getURI((*iUnhandledSym).uid, lName, lNameLen);
							// Convert the unhandled symbol into kPINodeName.
							(*iUnhandledSym).set(lName);
							(*iUnhandledSym).setPropID(mService.mProps[kPINodeName].uid);
						}
						// For a VT_STRUCT, just remove it (its uid, lPendingUid, will become the uid of the VT_STRUCT).
						else
						{
							if (1 == lStacked.size())
							{
								// For empty xml nodes as VT_STRUCT, make an exception: store an empty string as kPINodeValue.
								(*iUnhandledSym).set(copyStr(*pCtx->getSession(), "", 0));
								(*iUnhandledSym).setPropID(mService.mProps[kPINodeValue].uid);
							}
							else
								lStacked.erase(iUnhandledSym);
						}
					}

					// Allocate and initialize values for the new pin/VT_STRUCT (final in both cases, at this point).
					// Note: All strings/VT_STRUCT inside those Value-s were already ISession::malloc-ed for that purpose.
					size_t const lNumValues = lStacked.size();
					Value * const lValues = (Value *)pCtx->getSession()->malloc(lNumValues * sizeof(Value));
					memcpy(lValues, &lStacked[0], lNumValues * sizeof(Value));

					// Either create an uncommitted pin ready to be streamed out of the service (if this is an expected root,
					// or if this is the absolute root); or convert all this stuff into a VT_STRUCT value in the parent
					// (ready for future pin creation).
					if (lCreatePIN)
					{
						TMPDBG(report(AfyRC::MSG_DEBUG, "--   added a pin with %d values\n", lNumValues));

						// Create the pin.
						IPIN * lNewPIN = NULL;
						if (RC_OK == pCtx->getSession()->createPIN(lValues, (unsigned)lNumValues, &lNewPIN) && lNewPIN)
							mProduced.push_back(lNewPIN);
						else
						{
							report(AfyRC::MSG_DEBUG,"XmlServiceProc(%p): Failed to createUncommittedPIN with values:\n", this);
							reportValues(*pCtx->getSession(), lValues, lNumValues);
						}

						// Unstack.
						mSAXStack.pop_back();

						// Add a VT_REF to this pin, in the parent's properties.
						// TODO: Optionally add a VT_REF to the parent also... multi-pass...
						if (mSAXStack.size() > 0 && lNewPIN)
						{
							Value lVc;
							lVc.set(lNewPIN); lVc.setPropID(mService.mProps[kPINodeChildren].uid); lVc.op = OP_ADD; lVc.eid = STORE_LAST_ELEMENT;
							mSAXStack.back().push_back(lVc);
						}
					}
					else if (STORE_INVALID_URIID != lPendingUid)
					{
						TMPDBG(report(AfyRC::MSG_DEBUG, "--   converted %.200s into a VT_STRUCT with %d values\n", pName, lNumValues));
						mSAXStack.pop_back();
						Value lVs;
						lVs.setStruct(lValues, (uint32_t)lNumValues); lVs.setPropID(lPendingUid);
						mSAXStack.back().push_back(lVs);
					}
					else
						assert(false && "VT_STRUCT can only be the value of a non-pin symbol node");
				}
			protected:
				void readServiceConfig(IServiceCtx * pCtx)
				{
					// Obtain the service's parameters (to configure how we translate XML into PINs).
					// TODO: complete this (grouping, attributes, etc.).
					Value const * const lRoots = pCtx->getParameter(mService.mProps[kPIParameterRoots].uid);
					if (lRoots)
					{
						switch (lRoots->type)
						{
							case VT_COLLECTION: { for (uint32_t i = 0; i < lRoots->length; i++) if (VT_STRING == lRoots->varray[i].type) mRootNames.insert(lRoots->varray[i].str); break; }
							case VT_STRING: mRootNames.insert(lRoots->str); break;
							default: report(AfyRC::MSG_DEBUG,"XmlServiceProc(%p): Unexpected type for %.200s\n", this, mService.mProps[kPIParameterRoots].URI); break;
						}
					}
					Value const * const lOutputQnamePrefixes = pCtx->getParameter(mService.mProps[kPIParameterQnPrefixes].uid);
					if (lOutputQnamePrefixes)
					{
						switch (lOutputQnamePrefixes->type)
						{
							case VT_MAP:
							{
								RC lRC;
								Value const * lK, * lV;
								for (lRC = lOutputQnamePrefixes->map->getNext(lK, lV, true); RC_OK == lRC; lRC = lOutputQnamePrefixes->map->getNext(lK, lV))
								{
									if (!lK || !lV || VT_STRING != lK->type || VT_STRING != lV->type)
										{ report(AfyRC::MSG_DEBUG,"XmlServiceProc(%p): Unexpected value/key type for %.200s\n", this, mService.mProps[kPIParameterQnPrefixes].URI); continue; }
									addQnPrefix(lK->str, lV->str);
								}
								break;
							}
							default: report(AfyRC::MSG_DEBUG,"XmlServiceProc(%p): Unexpected type for %.200s\n", this, mService.mProps[kPIParameterQnPrefixes].URI); break;
						}
					}
					// Pre-configure afy:, srv: etc. (unless overriden by user config).
					char const * const lDefaultUris[] = {AFFINITY_STD_URI_PREFIX, AFFINITY_SERVICE_PREFIX};
					char const * const lDefaultPfxs[] = {AFFINITY_STD_QPREFIX, AFFINITY_SRV_QPREFIX};
					size_t iDef;
					for (iDef = 0; iDef < sizeof(lDefaultUris) / sizeof(lDefaultUris[0]); iDef++)
						addQnPrefix(lDefaultUris[iDef], lDefaultPfxs[iDef]);
				}
				void haveSAXParser()
				{
					if (mSAXParser)
						return;
					// Instantiate and configure the SAX parser.
					// Note:
					//   It seems that I don't need to do anything special about CDATA sections,
					//   they come as clean character data.  If users still want to annotate the PIN
					//   accordingly, it'd be trivial to handle XML_SetCdataSectionHandler
					//   (which only informs of '<![CDATA[' and ']]>').
					mSAXParser = XML_ParserCreateNS("UTF-8", '\xff');
					XML_SetUserData(mSAXParser, &mSAXParsingCtx);
					XML_SetStartElementHandler(mSAXParser, onStartElement_static);
					XML_SetCharacterDataHandler(mSAXParser, onCharacterData_static);
					XML_SetCommentHandler(mSAXParser, onComment_static);
					XML_SetEndElementHandler(mSAXParser, onEndElement_static);
					XML_SetStartNamespaceDeclHandler(mSAXParser, onStartNamespaceDecl_static);
				}
				URIID lookupSymbol(ISession & pSession, XML_Char const * pName)
				{
					// TODO: Measure the overhead(?) of calling map every time, vs caching it...
					// Note: Such a cache could also keep dual entries to avoid removing expat's ns separators every time...
					XML_Char const * lName = pName;
					XML_Char const * const lSeparator = strrchr((XML_Char *)pName, '\xff');
					bool lMustFree = false;
					if (lSeparator) // Note: expat forces us to manually remove the separator character, for expanded qnames...
					{
						size_t const lLen = strlen(pName);
						size_t const lToAlloc = lLen * sizeof(XML_Char); // Note: +1 for added \0, -1 for removed separator.
						lMustFree = lToAlloc > 4096;
						XML_Char * lCpy = (XML_Char *)(lMustFree ? pSession.malloc(lToAlloc) : alloca(lToAlloc));
						size_t const lSeparatorLen = lSeparator - pName;
						memcpy(lCpy, pName, lSeparatorLen);
						memcpy(lCpy + lSeparatorLen, &pName[lSeparatorLen + 1], lLen - lSeparatorLen - 1);
						lCpy[lLen - 1] = 0;
						lName = lCpy;
					}
					RC lRC;
					URIMap lPmap;
					lPmap.URI = lName; lPmap.uid = STORE_INVALID_URIID;
					if (RC_OK != (lRC = pSession.mapURIs(1, &lPmap)))
						report(AfyRC::MSG_DEBUG, "XmlServiceProc::lookupSymbol(%p): Failed to lookup symbol %.200s with RC=%d\n", lName, lRC);
					if (lMustFree)
						pSession.free((void *)lName);
					return lPmap.uid;
				}
			protected:
				void addQnPrefix(char const * pUri, char const * pPfx)
				{
					// Internally, normalize all names with trailing slash and no colon, for simplicity and uniformity
					// (n.b. libexpat expects the trailing '/' in the way it resolves namespace names).
					size_t const lUriLen = strlen(pUri); char * lUri = (char *)pUri;
					if (lUri[lUriLen - 1] != '/')
						{ lUri = (char *)alloca(lUriLen + 2); memcpy(lUri, pUri, lUriLen); lUri[lUriLen] = '/'; lUri[lUriLen + 1] = 0; }
					if (mQnPrefixes.end() != mQnPrefixes.find(lUri))
						return;
					size_t const lPfxLen = strlen(pPfx); char * lPfx = (char *)pPfx;
					if (lPfx[lPfxLen - 1] == ':')
						{ lPfx = (char *)alloca(lPfxLen); memcpy(lPfx, pPfx, lPfxLen); lPfx[lPfxLen - 1] = 0; }
					mQnPrefixes[lUri] = lPfx;
				}
				static XML_Char * copyStr(ISession & pSession, XML_Char const * pOriginal, int pLen)
				{
					XML_Char * lName = (XML_Char *)pSession.malloc((pLen + 1) * sizeof(XML_Char));
					memcpy(lName, pOriginal, pLen * sizeof(XML_Char));
					lName[pLen] = 0;
					return lName;
				}
				#if TMPDBGENABLE
					static void reportPIN(ISession & pSession, IPIN & pPIN)
					{
						std::ostringstream lOs;
						AfySerialization::ContextOutXml lXmlCtx(lOs, pSession);
						AfySerialization::OutXml::pin(lXmlCtx, pPIN);
						report(AfyRC::MSG_DEBUG, lOs.str().c_str());
					}
					static void reportValues(ISession & pSession, Value * pValues, size_t pNumValues)
					{
						std::ostringstream lOs;
						AfySerialization::ContextOutXml lXmlCtx(lOs, pSession);
						for (size_t i = 0; i < pNumValues; i++)
							AfySerialization::OutXml::value(lXmlCtx, pValues[i]);
						report(AfyRC::MSG_DEBUG, lOs.str().c_str());
					}
				#endif
		};
	protected:
		const URIMap * mProps;
	public:
		XmlService(URIMap *p) : mProps(p) {}
		virtual ~XmlService() {}
		virtual RC create(IServiceCtx *ctx,uint32_t& dscr,Processor *&ret)
		{
			switch (dscr&ISRV_PROC_MASK)
			{
				case ISRV_WRITE:
					dscr|=ISRV_ALLOCBUF;
				case ISRV_READ:
					dscr|=ISRV_NOCACHE; // Note: we cache our parameters internally, and also don't want to think about cleanup between usage sessions.
					if ((ret=new(ctx) XmlServiceProc(*this, ctx))==NULL) return RC_NOMEM;
					break;
				default:
					return RC_INVOP;
			}
			return RC_OK;
		}
};
char const * const XmlService::XmlServiceProc::sXMLTrailer = "</afyxml:result>\n\0";

extern "C" AFY_EXP bool SERVICE_INIT(XML)(ISession *ses,const Value *,unsigned,bool)
{
	IAffinity *ctx=ses->getAffinity();

	URIMap *pmap=(URIMap*)ctx->malloc(sizeof(sProps)/sizeof(sProps[0])*sizeof(URIMap)); if (pmap==NULL) return false;
	for (unsigned i=0; i<sizeof(sProps)/sizeof(sProps[0]); i++) {pmap[i].URI=sProps[i]; pmap[i].uid=STORE_INVALID_URIID;}
	if (ses->mapURIs(sizeof(sProps)/sizeof(sProps[0]),pmap)!=RC_OK) return false;
	TMPDBG(for (unsigned ii=0; ii<sizeof(sProps)/sizeof(sProps[0]); ii++) {printf("-- mapped prop %.200s to %d\n", pmap[ii].URI, pmap[ii].uid);});

	ctx->registerPrefix("XML", 3, XMLSERVICE_NAME "/", sizeof(XMLSERVICE_NAME));
	XmlService *xmls=new(ctx) XmlService(pmap);
	if (xmls==NULL || ctx->registerService(XMLSERVICE_NAME,xmls)!=RC_OK) return false;
	return true;
}

/*
  load service:
    CREATE LEADER _xml AS 'XML';
  input:
    INSERT afy:service={.srv:IO, .srv:XML}, XML:"config/roots"={'item'}, afy:address(READ_PERM)='/media/truecrypt1/src/maxw/mylab/afyservices/xmldata/rss_sports_01.xml', toto=1;
    SELECT * WHERE(toto=1);
    UPDATE * SET afy:position=0u WHERE(toto=1);
  output:
    INSERT afy:service={.srv:XML, .srv:IO}, XML:"config/output/qname/prefixes"={'http://purl.org/dc/terms'->'dcterms'}, afy:address=2, toto=2;
    UPDATE * SET afy:content=(SELECT *) WHERE(toto=2);
*/

// TODO (tests):
	// - test multi-roots, roots with ns, various patterns of roots in more complex xml, etc.
// TODO (input):
	// - finish afy:pin support (pin -> [xml -> pin])
	  // - may have to ignore/lazy-default some aspects for the moment, e.g. PID...
	// - finalize ISRV_flags for SAX (this should be fully supported already in k) - reevaluate once #394 is solved
	// - finish parsing and prop model (processing instr(?), doctype(?), etc.)
	// - go over all unfinished details once more (flags etc.)
	// - make sure all issues are represented in 1/more bug
	// - finalize internal doc
		// note: we're never going to stream "within a single pin (create+modify)" - except maybe for parent pins...
// TODO (output):
	// - encode &amp; etc.?
	// - review: <afy:element> ... probably not desired in xml -> pin -> xml... probably not needed in most cases also...
// TODO (in/out): test in more detail both scenarios of symmetry (xml -> pin -> xml, and pin -> xml -> pin)
// TODO (future):
  // - xml import/export: use stored preferred qname prefixes (as xml qnames), whenever possible (conclude disc with Mark first)
  // - export to xml: more ContextOutXml::eFlags (e.g. pin flags or not, etc.)
  // - export to xml: configuration for elements to be rendered as attributes (optional)
  // - export to xml: should there be an option to not use any xmlns? (e.g. afy:pin -> pin; scoped propnames -> some policy to reduce/concatenate/eliminate the scope) ... may be needed by some clients not processing xml namespaces
  // - export to xml: do something with non-pins as input?
  // - export to xml: prefetch (or delay processing) a few pins, to get a sense of common prefixes, and avoid as much as possible repetition of xmlns
  // - export to xml: configurable charsets/encodings/doctypes etc.
  // - export to xml: configurable cdata properties (?)
  // - xml import: bidirectional parent-child links... how, to preserve real streaming? partial commit of parent?
  // - xml import: more flexibility, e.g. for attributes (as pin, map, struct, coll; with/without ns etc.); grouping of props
  // - xml import: should we allow extra configuration to import non-prefixed xml into a specific affinity namespace? (could even accept a VT_MAP of names -> namespaces (i.e. "where" to put those simple names at import, in the global ns))
  // - xml import: should we allow ns translations (configurable)?
  // - xml import: q: should there be a version of the service that preserves absolute/global/nested order?
