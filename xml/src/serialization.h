/*
Copyright (c) 2004-2013 GoPivotal, Inc. All Rights Reserved.

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

#if !defined(_xml_serialization_h)
#define _xml_serialization_h

#include <affinity.h>
#include <startup.h>

#include <map>
#include <set>
#include <vector>
#include <string>
#include <ostream>
#include <istream>
#include <iomanip>
#include <iostream>
#include <algorithm>

#ifndef __APPLE__
#include <malloc.h>
#endif
#include <stdlib.h>
#include <search.h>
#include <assert.h>

using namespace Afy;

/**
 * External raw serialization/deserialization code for the affinity.
 * This is a stripped-down version, for xml output only.
 * Note:
 *   I departed from the original by
 *   a. moving all value types trailing space to endValue
 *   b. eliminating PrimitivesOutRaw
 *   Since this is now part of a service I doubt that I'll ever
 *   need to reconcile this code with the original version.
 */
namespace AfySerialization
{
	/**
	 * Out
	 * Entry-points to serialize affinity data.
	 */
	template <class TContextOut>
	class Out
	{
		public:
			inline static void value(TContextOut & pCtx, Value const & pValue);
			inline static void valueContent(TContextOut & pCtx, Value const & pValue, uint64_t pPersistedLen);
			inline static void property(TContextOut & pCtx, Value const & pValue);
			inline static void properties(TContextOut & pCtx, IPIN const & pPIN);
			inline static bool pin(TContextOut & pCtx, IPIN const & pPIN);
	};

	/**
	 * CollectionIterator
	 * Helper, to provide a uniform iteration interface for various types of collections.
	 */
	class CollectionIterator
	{
		protected:
			Value const & mCollection;
			unsigned long mI; // Note: May not be defined.
			ElementID mCurr;
		public:
			CollectionIterator(Value const & pCollection) : mCollection(pCollection), mI((unsigned long)-1), mCurr(0) {}
			inline Value const * beginAtIndex(unsigned long pIndex);
			inline Value const * beginAtEid(ElementID pEid);
			inline Value const * next();
			inline Value const * previous();
			inline void reset();
			inline static Value const * findValue(Value const & pCollection, ElementID pEid, unsigned long * pIt = NULL);
		private:
			CollectionIterator(CollectionIterator const &);
			CollectionIterator & operator =(CollectionIterator const &);
	};

	/**
	 * ContextOut
	 * Base classes for contextual information passed to serializers.
	 */
	class ContextOut
	{
		public:
			std::ostream & mOs;
			ISession * const mSession;
			bool const mStrict;
			bool const mOrderProps;
			std::streamsize mFloatPrecision, mDoublePrecision;
			ContextOut(std::ostream & pOs, ISession * pSession, bool pStrict, bool pOrderProps, std::streamsize pFloatPrecision = 8, std::streamsize pDoublePrecision = 18)
				: mOs(pOs), mSession(pSession)
				, mStrict(pStrict), mOrderProps(pOrderProps)
				, mFloatPrecision(pFloatPrecision), mDoublePrecision(pDoublePrecision) { mOs.imbue(std::locale::classic()); }
			std::ostream & os() const { return mOs; }
			ISession & session() const { return *mSession; }
			virtual ~ContextOut(){};
		private:
			ContextOut & operator=(ContextOut const &);
	};

	/*************************************************************************/

	/**
	 * Out implementation.
	 */
	template <class TContextOut>
	inline void Out<TContextOut>::valueContent(TContextOut & pCtx, Value const & pValue, uint64_t pPersistedLen)
	{
		static PID const lInvalidPID = {STORE_INVALID_PID, STORE_INVALID_IDENTITY};
		switch (pValue.type)
		{
			// Maps.
			case VT_MAP:
			{
				RC lRC;
				Value const * lK, * lV;
				for (lRC = pValue.map->getNext(lK, lV, true); RC_OK == lRC; lRC = pValue.map->getNext(lK, lV))
				{
					if (!lK || !lV)
						{ std::cerr << "Out<TContextOut>::valueContent warning: NULL key/value in VT_MAP" << std::endl; continue; }
					TContextOut::TPrimitives::keyvalue(pCtx, *lK, *lV);
				}
				break;
			}

			// Collections.
			case VT_STRUCT:
			{
				unsigned long i;
				for (i = 0; i < pValue.length; i++)
					property(pCtx, pValue.varray[i]);
				break;
			}
			case VT_COLLECTION:
				if (pValue.isNav())
				{
					size_t iV;
					Value const * lNext;
					assert(pValue.nav->count() == pPersistedLen && "Unhealthy collection [bug #5599]");
					for (lNext = pValue.nav->navigate(GO_FIRST), iV = 0; NULL != lNext && iV < pPersistedLen; lNext = pValue.nav->navigate(GO_NEXT), iV++)
						value(pCtx, *lNext);
					if (iV < pPersistedLen) // Note: Robustness for #5599 and potential similar issues (e.g. tx isolation issues).
					{
						Value lEmpty; lEmpty.setError(STORE_INVALID_URIID);
						for (; iV < pPersistedLen; iV++)
							value(pCtx, lEmpty);
					}
				}
				else
				{
					unsigned long i;
					for (i = 0; i < pValue.length; i++)
						value(pCtx, pValue.varray[i]);
				}
				break;
			case VT_RANGE:
			{
				unsigned long i;
				for (i = 0; i < pValue.length; i++)
					value(pCtx, pValue.range[i]);
				break;
			}

			// Streams.
			// Note: For replication, a different strategy may be adopted depending on pinet...
			case VT_STREAM:
			{
				IStream * lStream = pValue.stream.is;
				bool lCloned = false;
				if (RC_OK != lStream->reset())
					{ lStream = pValue.stream.is->clone(); lCloned = true; }
				switch (lStream->dataType())
				{
					case VT_STRING: case VT_BSTR: TContextOut::TPrimitives::outStream(pCtx, *pValue.stream.is, (char *)0, pPersistedLen); break;
					default: assert(false && "Unexisting stream format!"); break;
				}
				lCloned ? lStream->destroy() : (void)lStream->reset();
				break;
			}

			// Variable-length.
			case VT_STRING: TContextOut::TPrimitives::outString(pCtx, pValue.str, pValue.length); break;
			case VT_BSTR: TContextOut::TPrimitives::outString(pCtx, pValue.bstr, pValue.length); break;
			case VT_VARREF:
			{
				pCtx.os() << (int)pValue.refV.refN << " ";
				pCtx.os() << (int)pValue.refV.type;
				if (pValue.length == 1)
				{
					pCtx.os() << " ";
					TContextOut::TPrimitives::outURIID(pCtx, pValue.refV.id);
				}
				break;
			}
			case VT_STMT: TContextOut::TPrimitives::outQuery(pCtx, pValue); break;
			case VT_EXPR: TContextOut::TPrimitives::outExpr(pCtx, pValue); break;

			// Fixed-length.
			// Review: For VT_FLOAT/VT_DOUBLE, we could force std::fixed only for the hashing usage (#7905),
			//         instead of all usages, e.g. to limit the size of these values in a dump that would
			//         contain lots of them; for the moment it doesn't sound dramatic though, and
			//         backward compatibility should be trivial if we decide to change this later.
			case VT_ENUM: pCtx.os() << pValue.enu.enumid << "#" << pValue.enu.eltid; break;
			case VT_INT: pCtx.os() << pValue.i; break;
			case VT_UINT: pCtx.os() << pValue.ui; break;
			case VT_INT64: pCtx.os() << pValue.i64; break;
			case VT_UINT64: pCtx.os() << pValue.ui64; break;
			case VT_FLOAT: pCtx.os() << std::fixed << std::setprecision(pCtx.mFloatPrecision) << pValue.f; break;
			case VT_DOUBLE: pCtx.os() << std::fixed << std::setprecision(pCtx.mDoublePrecision) << pValue.d; break;
			case VT_BOOL: pCtx.os() << pValue.b; break;
			case VT_DATETIME: pCtx.os() << pValue.ui64; break;
			case VT_INTERVAL: pCtx.os() << pValue.i64; break;
			case VT_CURRENT: break;

			// References.
			// Review: It would be more efficient to persist a table and only index here...
			case VT_REF: TContextOut::TPrimitives::outRef(pCtx, pValue.pin ? pValue.pin->getPID() : lInvalidPID); break;
			case VT_REFID: TContextOut::TPrimitives::outRef(pCtx, pValue.id); break;
			case VT_REFPROP: TContextOut::TPrimitives::outRef(pCtx, pValue.ref.pin ? pValue.ref.pin->getPID() : lInvalidPID, pValue.ref.pid); break;
			case VT_REFIDPROP: TContextOut::TPrimitives::outRef(pCtx, pValue.refId->id, pValue.refId->pid, pValue.refId->eid); break;
			case VT_REFELT: TContextOut::TPrimitives::outRef(pCtx, pValue.ref.pin ? pValue.ref.pin->getPID() : lInvalidPID, pValue.ref.pid, pValue.ref.eid); break;
			case VT_REFIDELT: TContextOut::TPrimitives::outRef(pCtx, pValue.refId->id, pValue.refId->pid, pValue.refId->eid); break;
			case VT_IDENTITY: TContextOut::TPrimitives::outIID(pCtx, pValue.iid); break;
			case VT_URIID: TContextOut::TPrimitives::outURIID(pCtx, pValue.uid); break;

			// Delete.
			case VT_ERROR: break;

			// TODO
			case VT_EXPRTREE:
			default:
				assert(!pCtx.mStrict && "Not yet implemented persistence required in real life!");
				break;
		}
	}

	template <class TContextOut>
	static inline void outValue(TContextOut & pCtx, Value const & pValue)
	{
		uint64_t lPersistedLen;
		TContextOut::TPrimitives::beginValue(pCtx, pValue, &lPersistedLen);
		Out<TContextOut>::valueContent(pCtx, pValue, lPersistedLen);
		// Special treatment for OP_EDIT...
		if (OP_EDIT == pValue.op)
		{
			pCtx.os() << pValue.edit.length << " ";
			pCtx.os() << pValue.edit.shift;
		}
		TContextOut::TPrimitives::endValue(pCtx, pValue);
	}

	template <class TContextOut>
	inline void Out<TContextOut>::value(TContextOut & pCtx, Value const & pValue)
	{
		outValue<TContextOut>(pCtx, pValue);
	}

	template <class TContextOut>
	static inline void outProperty(TContextOut & pCtx, Value const & pValue)
	{
		if (TContextOut::TPrimitives::beginProperty(pCtx, pValue.property))
		{
			Out<TContextOut>::value(pCtx, pValue);
			TContextOut::TPrimitives::endProperty(pCtx, pValue.property);
		}
	}

	template <class TContextOut>
	inline void Out<TContextOut>::property(TContextOut & pCtx, Value const & pValue)
	{
		outProperty<TContextOut>(pCtx, pValue);
	}

	struct PropertyNameAndID
	{
		char * mName;
		PropertyID mPropID;
		static int compare(const void * p1, const void * p2) { return strcmp(((PropertyNameAndID *)p1)->mName, ((PropertyNameAndID *)p2)->mName); }
		static void sortProperties(ISession * pSession, IPIN const & pPIN, unsigned const pNumberOfProperties, PropertyNameAndID * pResult)
		{
			unsigned i;
			assert(pNumberOfProperties == pPIN.getNumberOfProperties());
			for (i = 0; i < pNumberOfProperties; i++)
			{
				Value const * const lV = pPIN.getValueByIndex(i);
				if (!lV)
					continue;
				pResult[i].mPropID = lV->getPropID();
				size_t lSize = 0;
				if (pSession) pSession->getURI(pResult[i].mPropID, NULL, lSize);
				if (lSize > 0)
				{
					pResult[i].mName = new char[1 + lSize];
					pResult[i].mName[lSize++] = 0;
					pSession->getURI(pResult[i].mPropID, pResult[i].mName, lSize);
				}
				else
				{
					pResult[i].mName = new char[32];
					sprintf(pResult[i].mName, "%u", pResult[i].mPropID);

					static bool sWarned = false;
					if (!sWarned && (NULL != pSession))
					{
						std::cerr << "sortProperties warning: PropertyID not registered!" << std::endl << std::flush;
						sWarned = true;
					}
				}
			}
			qsort(pResult, pNumberOfProperties, sizeof(PropertyNameAndID), &PropertyNameAndID::compare);
		}
	};

	template <class TContextOut>
	inline void Out<TContextOut>::properties(TContextOut & pCtx, IPIN const & pPIN)
	{
		unsigned i;
		unsigned const lNumberOfProperties = pPIN.getNumberOfProperties();
		if (pCtx.mOrderProps)
		{
			PropertyNameAndID * const lSorted = (PropertyNameAndID *)alloca(lNumberOfProperties * sizeof(PropertyNameAndID));
			PropertyNameAndID::sortProperties(pCtx.mSession, pPIN, lNumberOfProperties, lSorted);
			for (i = 0; i < lNumberOfProperties; i++)
			{
				Value const * const lV = pPIN.getValue(lSorted[i].mPropID);
				if (!lV)
				{
					std::cerr << "Out<TContextOut>::properties warning: NULL value for property " << lSorted[i].mPropID << std::endl;
					continue;
				}
				property(pCtx, *lV);
				delete [] lSorted[i].mName;
			}
		}
		else
		{
			for (i = 0; i < lNumberOfProperties; i++)
			{
				Value const * const lV = pPIN.getValueByIndex(i);
				property(pCtx, *lV);
			}
		}
	}

	template <class TContextOut>
	inline bool Out<TContextOut>::pin(TContextOut & pCtx, IPIN const & pPIN)
	{
		if (!TContextOut::TPrimitives::beginPIN(pCtx, pPIN))
			return false;
		properties(pCtx, pPIN);
		TContextOut::TPrimitives::endPIN(pCtx, pPIN);
		return true;
	}

	/**
	 * CollectionIterator implementation.
	 */
	inline Value const * CollectionIterator::beginAtIndex(unsigned long pIndex)
	{
		reset();
		Value const * lV;
		if (mCollection.type==Afy::VT_COLLECTION || mCollection.type==Afy::VT_STRUCT)
		{
			if (mCollection.type==Afy::VT_STRUCT || !mCollection.isNav())
			{
				for (mI = 0; mI < pIndex && mI < mCollection.length; mI++);
				mCurr = (mI < mCollection.length) ? mCollection.varray[mI].eid : 0;
				return (mI < mCollection.length) ? &mCollection.varray[mI] : NULL;
			}
			else
			{
				for (lV = mCollection.nav->navigate(GO_FIRST), mI = 0; mI < pIndex && lV; lV = mCollection.nav->navigate(GO_NEXT), mI++);
				mCurr = lV ? lV->eid : 0;
				return lV;
			}
		}
		if (0 == pIndex)
			{ mI = 0; mCurr = mCollection.eid; return &mCollection; }
		return NULL;
	}

	inline Value const * CollectionIterator::beginAtEid(ElementID pEid)
	{
		reset();
		Value const * const lV = findValue(mCollection, pEid, &mI);
		mCurr = lV ? lV->eid : 0;
		if (lV && (unsigned long)-1 == mI)
			mI = 0;
		return lV;
	}

	inline Value const * CollectionIterator::next()
	{
		if ((unsigned long)-1 == mI || 0 == mCurr)
			return NULL; // Iteration not started.
		Value const * lV;
		if (mCollection.type==Afy::VT_COLLECTION || mCollection.type==Afy::VT_STRUCT)
		{
			if (mCollection.type==Afy::VT_STRUCT || !mCollection.isNav())
			{
				mI++;
				if (mI < mCollection.length)
					{ mCurr = mCollection.varray[mI].eid; return &mCollection.varray[mI]; }
				return NULL;
			}
			else
			{
				lV = mCollection.nav->navigate(GO_NEXT);
				mCurr = lV ? lV->eid : 0;
				return lV;
			}
		}
		return NULL;
	}

	inline Value const * CollectionIterator::previous()
	{
		if ((unsigned long)-1 == mI || 0 == mCurr)
			return NULL; // Iteration not started.
		Value const * lV;
		if (mCollection.type==Afy::VT_COLLECTION || mCollection.type==Afy::VT_STRUCT)
		{
			if (mCollection.type==Afy::VT_STRUCT || !mCollection.isNav())
			{
				if (mI > 0)
					{--mI; mCurr = mCollection.varray[mI].eid; return &mCollection.varray[mI]; }
				return NULL;
			}
			else
			{
				lV = mCollection.nav->navigate(GO_PREVIOUS);
				mCurr = lV ? lV->eid : 0;
				return lV;
			}
		}
		return NULL;
	}

	inline void CollectionIterator::reset()
	{
		mI = (unsigned long)-1;
		mCurr = 0;
	}

	inline Value const * CollectionIterator::findValue(Value const & pCollection, ElementID pEid, unsigned long * pIt)
	{
		// Warning: Usage of this function can result in O(n.log(n)), or O(n^2) patterns
		//          (the latter case would be expected for small collections only).
		if (pIt)
			*pIt = (unsigned long)-1;
		unsigned long i;
		if (pCollection.type==Afy::VT_COLLECTION || pCollection.type==Afy::VT_STRUCT)
		{
			if (pCollection.type==Afy::VT_STRUCT || !pCollection.isNav())
			{
				if (pEid == STORE_FIRST_ELEMENT)
					i = 0;
				else if (pEid == STORE_LAST_ELEMENT)
					i = pCollection.length > 0 ? pCollection.length - 1 : 0;
				else
					for (i = 0; i < pCollection.length && pCollection.varray[i].eid != pEid; i++);
				if (pIt)
					*pIt = i;
				return (i < pCollection.length) ? &pCollection.varray[i] : NULL;
			}
			else
			{
				return pCollection.nav->navigate(Afy::GO_FINDBYID, pEid);
			}
		}
		return (pCollection.eid == pEid || STORE_FIRST_ELEMENT == pEid || STORE_LAST_ELEMENT == pEid) ? &pCollection : NULL;
	}

	/*************************************************************************
	 * XML Output
	 * (Used to be taken care of by XQuery; I only take care of output here;
	 * input is implemented in a service and relies on a 3rd-party SAX parser)
	 *************************************************************************/

	class PrimitivesOutXml;
	class ContextOutXml : public ContextOut
	{
		public:
			typedef std::set<URIID> TURIIDs;
			typedef std::map<std::string, std::string> TURIPrefix2QnamePrefix;
			struct PinStackItem
			{
				IPIN const * mPin;
				URIID mElmName;
				TURIPrefix2QnamePrefix mPrefixes;
				TURIIDs mKnownURIIDs; // To avoid extracting xml prefixes for every single property...
				PinStackItem(IPIN const * pPin, URIID pElmName) : mPin(pPin), mElmName(pElmName) {}
				struct Pred_KnowsPin { IPIN const * const mPin; Pred_KnowsPin(IPIN const * pPin) : mPin(pPin) {}; bool operator()(PinStackItem const & pI) const { return pI.mPin == mPin || pI.mPin->getPID() == mPin->getPID(); } };
				struct Pred_KnowsURIID { URIID const mURIID; Pred_KnowsURIID(URIID pURIID) : mURIID(pURIID) {}; bool operator()(PinStackItem const & pI) const { return pI.mKnownURIIDs.end() != pI.mKnownURIIDs.find(mURIID); } };
				struct Pred_KnowsURIPrefix { char const * const mURIPrefix; Pred_KnowsURIPrefix(char const * pURIPrefix) : mURIPrefix(pURIPrefix) {}; bool operator()(PinStackItem const & pI) const { return pI.mPrefixes.end() != pI.mPrefixes.find(mURIPrefix); } };
			};
		public:
			struct CollStackItem { long mLevel; long mPropId; ValueType mVT; CollStackItem(long pLevel, long pPropId, ValueType pVT) : mLevel(pLevel), mPropId(pPropId), mVT(pVT) {} };
			typedef std::vector<PinStackItem> TPinStack;
			typedef std::vector<CollStackItem> TCollStack;
			enum eFlags { kFRecurseRefs = (1 << 0), kFWithPresentation = (1 << 1), kFDefault = (kFRecurseRefs | kFWithPresentation), };
		public:
			enum eImportConvention
			{
				kICFIRST = 0,
				kICNodeName = kICFIRST,
				kICNodeValue,
				kICNodeParent,
				kICNodeChildren,
				kICNodeAttributes,
				kICComment,
				kICTOTAL
			};
		public:
			TPinStack mPinStack;
			TCollStack mCollStack;
			TURIPrefix2QnamePrefix mPreferredPrefixes;
			URIMap const * mImportConvention;
			long mFlags;
			long mLevel;
			long mNextAutoPrefixNum;
		public:
			typedef PrimitivesOutXml TPrimitives;
			ContextOutXml(std::ostream & pOs, ISession & pSession, long pFlags = kFDefault, long pLevel = 0) : ContextOut(pOs, &pSession, false, true), mImportConvention(NULL), mFlags(pFlags) { clear(); mLevel = pLevel; }
			void setPreferredPrefixes(TURIPrefix2QnamePrefix const * pPP)
			{
				// The preferred convention in ContextOutXml is for all prefix definitions to not
				// contain the trailing slash.  Here we make sure that the externally provided
				// prefixes follow this convention.
				mPreferredPrefixes.clear();
				if (!pPP)
					return;
				for (TURIPrefix2QnamePrefix::const_iterator iP = pPP->begin(); pPP->end() != iP; iP++)
				{
					std::string const & lK = (*iP).first;
					mPreferredPrefixes.insert(TURIPrefix2QnamePrefix::value_type(
						(lK.at(lK.length() - 1) == '/' ? lK.substr(0, lK.length() - 1) : lK), (*iP).second));
				}
			}
			void setImportConvention(URIMap const * pPropMaps) { mImportConvention = pPropMaps; }
			void clear() { mPinStack.clear(); mCollStack.clear(); mPreferredPrefixes.clear(); mImportConvention = NULL; mLevel = 0; mNextAutoPrefixNum = 0; }
			bool recurseRefs() const { return 0 != (mFlags & kFRecurseRefs); }
			bool withPresentation() const { return 0 != (mFlags & kFWithPresentation); }
		public:
			void analyzePrefix(char * pPropURI/*warning:destructive*/, URIID pPropID)
			{
				// Find out if it contains a /; if it doesn't, then it's not a candidate for prefix extraction.
				char * const lLastSlash = strrchr(pPropURI, '/');
				if (!lLastSlash)
					return;

				// Make sure this URI and its prefix will be taken into consideration in subsequent calls to findQnamePrefix/outURIID.
				*lLastSlash = 0; // Note: this is our own copy...
				TURIPrefix2QnamePrefix::const_iterator iPP;
				TPinStack::iterator iPS;
				if (mPreferredPrefixes.end() != (iPP = mPreferredPrefixes.find(pPropURI)))
					mPinStack.back().mKnownURIIDs.insert(pPropID);
				else if (mPinStack.end() == (iPS = std::find_if(mPinStack.begin(), mPinStack.end(), PinStackItem::Pred_KnowsURIPrefix(pPropURI))))
				{
					char lQnamePrefix[32]; sprintf(lQnamePrefix, "qn%ld", ++mNextAutoPrefixNum);
					mPinStack.back().mPrefixes[pPropURI] = lQnamePrefix;
					mPinStack.back().mKnownURIIDs.insert(pPropID);
				}
				else
					(*iPS).mKnownURIIDs.insert(pPropID);
			}
			void analyzePrefix(URIID pPropID)
			{
				// First, find out if pPropID is already known.
				if (mPinStack.end() != std::find_if(mPinStack.begin(), mPinStack.end(), PinStackItem::Pred_KnowsURIID(pPropID)))
					return;
				// At this stage we need to get the actual URI.
				size_t lURISize = 0;
				session().getURI(pPropID, NULL, lURISize, true);
				char * const lURI = (char *)alloca(1 + lURISize);
				lURI[lURISize++] = 0;
				session().getURI(pPropID, lURI, lURISize, true);
				analyzePrefix(lURI, pPropID);
			}
			void analyzePrefix(Value const & pV)
			{
				analyzePrefix(pV.property);
				if (VT_STRUCT == pV.type)
				{
					CollectionIterator lCI(pV);
					for (Value const * iV = lCI.beginAtIndex(0); iV; iV = lCI.next())
						analyzePrefix(*iV);
				}
			}
			std::string const & findQnamePrefix(char const * pURIPrefix) const
			{
				// Check global configuration.
				TURIPrefix2QnamePrefix::const_iterator iPP;
				if (mPreferredPrefixes.end() != (iPP = mPreferredPrefixes.find(pURIPrefix)))
					return (*iPP).second;

				// Check pin stack.
				TPinStack::const_iterator iPS;
				for (iPS = mPinStack.begin(); mPinStack.end() != iPS; iPS++)
				{
					TURIPrefix2QnamePrefix::const_iterator iP = (*iPS).mPrefixes.find(pURIPrefix);
					if ((*iPS).mPrefixes.end() != iP)
						return (*iP).second;
				}

				// Just in case.
				static std::string sNothing;
				return sNothing;
			}
	};

	typedef Out<ContextOutXml> OutXml;

	class PrimitivesOutXml
	{
		public:
			template <class T> inline static void outString(ContextOutXml & pCtx, T const * pString, uint32_t pLenInB);
			template <class T> inline static void outStream(ContextOutXml & pCtx, IStream & pStream, T * pT, uint64_t pLenInB = uint64_t(~0));
			inline static void outQuery(ContextOutXml & pCtx, Value const & pValue);
			inline static void outExpr(ContextOutXml & pCtx, Value const & pValue);
			inline static void outIID(ContextOutXml & pCtx, IdentityID const & pIID);
			inline static void outRef(ContextOutXml & pCtx, PID const & pPID);
			inline static void outRef(ContextOutXml & pCtx, PID const & pPID, PropertyID const & pPropID);
			inline static void outRef(ContextOutXml & pCtx, PID const & pPID, PropertyID const & pPropID, ElementID const & pEid);
			inline static void outCLSID(ContextOutXml & pCtx, ClassID const & pCLSID);
			inline static void outClassSpec(ContextOutXml & pCtx, SourceSpec const & pClassSpec);
			inline static void outDateTime(ContextOutXml & pCtx, DateTime const & pDateTime);
			inline static void outURIID(ContextOutXml & pCtx, PropertyID const & pPropID);
			inline static void keyvalue(ContextOutXml & pCtx, Value const & pKey, Value const & pValue);
			inline static void beginValue(ContextOutXml & pCtx, Value const & pValue, uint64_t * pLen);
			inline static void endValue(ContextOutXml & pCtx, Value const & pValue);
			inline static bool beginProperty(ContextOutXml & pCtx, PropertyID const & pPropID) { if (pCtx.mImportConvention) { for (int i = ContextOutXml::kICFIRST; i < ContextOutXml::kICTOTAL; i++) { if (pCtx.mImportConvention[i].uid == pPropID) return false; } } return true; }
			inline static void endProperty(ContextOutXml &, PropertyID const &) {}
			inline static bool beginPIN(ContextOutXml & pCtx, IPIN const & pPIN);
			inline static void endPIN(ContextOutXml & pCtx, IPIN const & pPIN);
		public:
			static std::ostream & outTab(ContextOutXml & pCtx) { if (pCtx.withPresentation()) { for (long i = 0; i < pCtx.mLevel; i++) pCtx.os() << "  "; } return pCtx.os(); }
			static std::ostream & outEndl(ContextOutXml & pCtx) { if (pCtx.withPresentation()) { pCtx.os() << std::endl; } return pCtx.os(); }
		protected:
			inline static Value const * findValueOf(ContextOutXml & pCtx, Value const & pParent, ContextOutXml::eImportConvention pType);
			inline static Value const * findValueOf(ContextOutXml & pCtx, IPIN const & pParent, ContextOutXml::eImportConvention pType);
			inline static void renderAttributes(ContextOutXml & pCtx, Value const * pStruct);
	};

	/**
	 * PrimitivesOutRaw implementation.
	 */
	template <class T>
	inline void PrimitivesOutXml::outString(ContextOutXml & pCtx, T const * pString, uint32_t pLenInB)
	{
		if (!pString || !pLenInB)
			return;
		if (NULL != strpbrk((char const *)pString, "<>"))
		{
			// Review: Is this the best way to handle this?
			// Review: e.g. in a 'kICComment' property, we don't want to do this...
			pCtx.os() << "<![CDATA[";
			pCtx.os().write((char const *)pString, pLenInB);
			pCtx.os() << "]]>";
		}
		else
			pCtx.os().write((char const *)pString, pLenInB);
	}

	template <class T>
	inline void PrimitivesOutXml::outStream(ContextOutXml & pCtx, IStream & pStream, T *, uint64_t pLenInB)
	{
		if (0 == pLenInB)
			return;
		int lIsCDATA = -1;
		T lBuf[0x1000];
		size_t lRead;
		uint64_t lTotalReadInB;
		for (lRead = pStream.read(lBuf, 0x1000), lTotalReadInB = 0;
			0 != lRead && lTotalReadInB < pLenInB;
			lRead = pStream.read(lBuf, 0x1000))
		{
			if (-1 == lIsCDATA)
			{
				for (size_t i = 0; i < lRead && -1 == lIsCDATA; i++)
					{ if (lBuf[i] == '<' || lBuf[i] == '>') lIsCDATA = 1; }
				if (1 == lIsCDATA)
					pCtx.os() << "<![CDATA[";
				else
					lIsCDATA = 0;
			}
			lTotalReadInB += lRead;
			if (lTotalReadInB > pLenInB)
			{
				std::cerr << "PrimitivesOutXml warning: pStream returned more bytes than expected! (old bug 7938?)" << std::endl;
				lRead -= (unsigned long)(lTotalReadInB - pLenInB);
				lTotalReadInB = pLenInB;
			}
			outString(pCtx, lBuf, (uint32_t)lRead);
		}
		if (uint64_t(~0) != pLenInB && lTotalReadInB < pLenInB)
		{
			std::cerr << "PrimitivesOutXml warning: pStream returned less bytes than expected! (old bug 7938?)" << std::endl;
			memset(lBuf, 0, sizeof(lBuf));
			do
			{
				lRead = (pLenInB - lTotalReadInB) > sizeof(lBuf) ? sizeof(lBuf) : (unsigned long)(pLenInB - lTotalReadInB);
				outString(pCtx, lBuf, (uint32_t)lRead);
				lTotalReadInB += lRead;
			} while (lTotalReadInB < pLenInB);
		}
		if (1 == lIsCDATA)
			pCtx.os() << "]]>";
	}

	inline void PrimitivesOutXml::outQuery(ContextOutXml & pCtx, Value const & pValue)
	{
		char * const lSer = pValue.stmt->toString();
		uint32_t const lSerLen = uint32_t(strlen(lSer));
		outString(pCtx, lSer, lSerLen);
		pCtx.session().free(lSer);
	}

	inline void PrimitivesOutXml::outExpr(ContextOutXml & pCtx, Value const & pValue)
	{
		char * const lSer = pValue.expr->toString();
		uint32_t const lSerLen = uint32_t(strlen(lSer));
		outString(pCtx, lSer, lSerLen);
		pCtx.session().free(lSer);
	}

	inline void PrimitivesOutXml::outIID(ContextOutXml & pCtx, IdentityID const & pIID)
	{
		size_t const lIdentityNameSize = (STORE_OWNER == pIID) ? 0 : pCtx.session().getIdentityName(pIID, NULL, 0);
		size_t const lIdentityKeySize = (STORE_OWNER == pIID) ? 0 : pCtx.session().getCertificate(pIID, NULL, 0);
		if (0 == lIdentityNameSize)
		{
			pCtx.os() << pIID;
			static bool sWarned = false;
			if (!sWarned && STORE_OWNER != pIID)
			{
				std::cerr << "PrimitivesOutXml warning: IdentityID not registered!" << std::endl << std::flush;
				sWarned = true;
			}
		}
		else
		{
			char * const lIdentityName = (char *)alloca(1 + lIdentityNameSize);
			unsigned char * const lIdentityKey = (unsigned char *)alloca(1 + lIdentityKeySize);
			lIdentityName[lIdentityNameSize] = 0;
			lIdentityKey[lIdentityKeySize] = 0;
			pCtx.session().getIdentityName(pIID, lIdentityName, 1 + lIdentityNameSize);
			pCtx.session().getCertificate(pIID, lIdentityKey, 1 + lIdentityKeySize);
			pCtx.os().write(lIdentityName, (int)lIdentityNameSize); pCtx.os() << " ";
			pCtx.os().write((char *)lIdentityKey, (int)lIdentityKeySize);
		}
	}

	inline void PrimitivesOutXml::outRef(ContextOutXml & pCtx, PID const & pPID)
	{
		if (pCtx.recurseRefs())
		{
			IPIN * const lPIN = pCtx.session().getPIN(pPID);
			if (lPIN)
			{
				ContextOutXml lCtx(pCtx);
				lCtx.mLevel++; // Note: lCtx is a temporary ctx...
				outEndl(pCtx);
				Out<ContextOutXml>::pin(lCtx, *lPIN);
				lPIN->destroy();
				outTab(pCtx);
				return;
			}
		}
		if (STORE_OWNER != pPID.ident)
			{ outIID(pCtx, pPID.ident); pCtx.os() << ":"; } // Review: adopt an official convention for this kind of extended pid...
		pCtx.os() << "@" << std::hex << pPID.pid << std::dec;
	}

	inline void PrimitivesOutXml::outRef(ContextOutXml & pCtx, PID const & pPID, PropertyID const & pPropID)
	{
		long const lOldFlags = pCtx.mFlags; pCtx.mFlags &= ~ContextOutXml::kFRecurseRefs;
		outRef(pCtx, pPID);
		pCtx.os() << ".";
		outURIID(pCtx, pPropID);
		pCtx.mFlags = lOldFlags;
	}

	inline void PrimitivesOutXml::outRef(ContextOutXml & pCtx, PID const & pPID, PropertyID const & pPropID, ElementID const & pEid)
	{
		outRef(pCtx, pPID, pPropID);
		pCtx.os() << "[" << std::hex << pEid << std::dec << "]"; // Review: dec or hex?
	}

	inline void PrimitivesOutXml::outCLSID(ContextOutXml & pCtx, ClassID const & pCLSID)
	{
		IPIN * lCInfo = NULL;
		pCtx.session().getClassInfo(pCLSID, lCInfo);
		if (lCInfo)
		{
		  Value const * lCName = lCInfo->getValue(PROP_SPEC_OBJID);
		  if (lCName)
			  { pCtx.os() << lCName->str; lCInfo->destroy(); return; }
		  lCInfo->destroy();
		}
		pCtx.os() << pCLSID;
	}

	inline void PrimitivesOutXml::outClassSpec(ContextOutXml & pCtx, SourceSpec const & pClassSpec)
	{
		outURIID(pCtx, pClassSpec.objectID);
		pCtx.os() << "{";
		unsigned i;
		for (i = 0; i < pClassSpec.nParams; i++)
		{
			Out<ContextOutXml>::value(pCtx, pClassSpec.params[i]);
			if (i + 1 < pClassSpec.nParams)
				pCtx.os() << ",";
		}
		pCtx.os() << "}";
	}

	inline void PrimitivesOutXml::outDateTime(ContextOutXml & pCtx, DateTime const & pDateTime)
	{
		pCtx.os() << pDateTime.year << "-"; // Review: adjustments required?
		pCtx.os() << pDateTime.month << "-";
		pCtx.os() << pDateTime.day << " ";
		pCtx.os() << pDateTime.hour << ":";
		pCtx.os() << pDateTime.minute << ":";
		pCtx.os() << pDateTime.second << ".";
		pCtx.os() << pDateTime.microseconds;
	}

	inline void PrimitivesOutXml::outURIID(ContextOutXml & pCtx, PropertyID const & pPropID)
	{
		size_t lPropertyURISize = 0;
		char const * lPropertyURI = NULL;
		if (RC_OK == pCtx.session().getURI(pPropID, NULL, lPropertyURISize, true) && 0 != lPropertyURISize)
		{
			lPropertyURI = (char const *)alloca(1 + lPropertyURISize);
			((char *)lPropertyURI)[lPropertyURISize++] = 0;
			pCtx.session().getURI(pPropID, (char *)lPropertyURI, lPropertyURISize, true);
		}
		else 
		{
			lPropertyURI = "afy:unknown";
		}

		if (lPropertyURI)
		{
			char * lLastSlash = (char *)strrchr(lPropertyURI, '/');
			if (lLastSlash)
			{
				*lLastSlash = 0; // Note: this is our own copy...
				pCtx.os() << pCtx.findQnamePrefix(lPropertyURI) << ":" << &lLastSlash[1];
			}
			else
				pCtx.os() << lPropertyURI;
		}
	}

	inline bool PrimitivesOutXml::beginPIN(ContextOutXml & pCtx, IPIN const & pPIN)
	{
		// Start the pin element.
		URIID lElmName = STORE_INVALID_URIID;
		if (pCtx.mImportConvention)
		{
			// See if this pin contains a "node name" property, according to mImportConvention.
			// This is to provide some degree of symmetry in a xml -> pin -> xml scenario
			// (i.e. properties generated during import are taken into consideration during export).
			Value const * lVuri = pPIN.getValue(pCtx.mImportConvention[ContextOutXml::kICNodeName].uid);
			if (lVuri && VT_STRING == lVuri->type)
			{
				// If so, its value should be a URI, and we'll need its uid.
				RC lRC;
				URIMap lPmap;
				lPmap.URI = lVuri->str; lPmap.uid = STORE_INVALID_URIID;
				if (RC_OK != (lRC = pCtx.session().mapURIs(1, &lPmap)))
					std::cerr << "PrimitivesOutXml warning: Failed to mapURIs for " << lPmap.URI << " in beginPIN" << std::endl;
				else
				{
					// Make sure its xmlns prefix is taken care of, and produce the expected element name.
					lElmName = lPmap.uid;
					char * lURI = (char *)alloca(1 + lVuri->length);
					memcpy(lURI, lVuri->str, lVuri->length);
					lURI[lVuri->length] = 0;
					pCtx.analyzePrefix(lURI, lElmName);
					outTab(pCtx) << "<"; outURIID(pCtx, lElmName); // Note: don't close the element yet.
				}
			}
		}
		if (STORE_INVALID_URIID == lElmName)
		{
			outTab(pCtx) << "<afyxml:PIN afy:pinID=\"";
			long const lOldFlags = pCtx.mFlags; pCtx.mFlags &= ~ContextOutXml::kFRecurseRefs;
			outRef(pCtx, pPIN.getPID());
			pCtx.mFlags = lOldFlags;
			pCtx.os() << "\"";
		}

		// Detect cycles.
		if (pCtx.mPinStack.end() != std::find_if(pCtx.mPinStack.begin(), pCtx.mPinStack.end(), ContextOutXml::PinStackItem::Pred_KnowsPin(&pPIN)))
			{ outTab(pCtx) << " afyxml:cycle=true />"; outEndl(pCtx); return false; }
		pCtx.mPinStack.push_back(ContextOutXml::PinStackItem(&pPIN, lElmName));

		// Find out if new xmlns prefixes need to be declared at this level.
		unsigned const lNumberOfProperties = pPIN.getNumberOfProperties();
		for (unsigned i = 0; i < lNumberOfProperties; i++)
			pCtx.analyzePrefix(*pPIN.getValueByIndex(i));
		for (ContextOutXml::TURIPrefix2QnamePrefix::iterator iP = pCtx.mPinStack.back().mPrefixes.begin(); pCtx.mPinStack.back().mPrefixes.end() != iP; iP++)
			pCtx.os() << " xmlns:" << (*iP).second.c_str() << "=\"" << (*iP).first.c_str() << "\"";

		// Any attributes?
		renderAttributes(pCtx, findValueOf(pCtx, pPIN, ContextOutXml::kICNodeAttributes));

		// Start of pin element is complete.
		pCtx.os() << ">"; outEndl(pCtx);
		return true;
	}

	inline void PrimitivesOutXml::endPIN(ContextOutXml & pCtx, IPIN const &)
	{
		URIID const lElmName = pCtx.mPinStack.back().mElmName;
		if (STORE_INVALID_URIID == lElmName)
			{ outTab(pCtx) << "</afyxml:PIN>"; outEndl(pCtx); }
		else
			{ outTab(pCtx) << "</"; outURIID(pCtx, lElmName); pCtx.os() << ">"; outEndl(pCtx); }
		pCtx.mPinStack.pop_back();
	}

	inline void PrimitivesOutXml::keyvalue(ContextOutXml & pCtx, Value const & pKey, Value const & pValue)
	{
		outTab(pCtx) << "<afyxml:mapentry afyxml:key=\"";
		Out<ContextOutXml>::value(pCtx, pKey);
		pCtx.os() << "\" afyxml:value=\"";
		Out<ContextOutXml>::value(pCtx, pValue);
		pCtx.os() << "\" />";
		outEndl(pCtx);
	}

	inline void PrimitivesOutXml::beginValue(ContextOutXml & pCtx, Value const & pValue, uint64_t *)
	{
		// Review: Maybe this is abusive in some cases (push back some of that stuff to beginProperty?)...
		pCtx.mLevel++;
		bool lDefault = (pCtx.mCollStack.empty() || pCtx.mCollStack.back().mLevel != pCtx.mLevel - 1);
		if (!lDefault)
		{
			switch (pCtx.mCollStack.back().mVT)
			{
				case VT_MAP: break;
				case VT_STRUCT: lDefault = true; break;
				default: { outTab(pCtx) << "<afyxml:element>"; break; }
			}
		}
		if (lDefault)
		{
			outTab(pCtx) << "<";
			outURIID(pCtx, pValue.getPropID());
			renderAttributes(pCtx, findValueOf(pCtx, pValue, ContextOutXml::kICNodeAttributes));
			pCtx.os() << ">";
		}

		if (VT_COLLECTION == pValue.type || VT_STRUCT == pValue.type || VT_MAP == pValue.type)
		{
			pCtx.mLevel++;
			pCtx.mCollStack.push_back(ContextOutXml::CollStackItem(pCtx.mLevel, pValue.property, (ValueType)pValue.type));
			outEndl(pCtx);
		}
	}

	inline void PrimitivesOutXml::endValue(ContextOutXml & pCtx, Value const & pValue)
	{
		bool const lIsContainer = (VT_COLLECTION == pValue.type || VT_STRUCT == pValue.type || VT_MAP == pValue.type);
		if (lIsContainer)
		{
			pCtx.mCollStack.pop_back();
			pCtx.mLevel--;
			outTab(pCtx);
		}

		ValueType const lParentVT = ((pCtx.mCollStack.empty() || (pCtx.mLevel - 1) != pCtx.mCollStack.back().mLevel) ? VT_ANY : pCtx.mCollStack.back().mVT);
		switch (lParentVT)
		{
			case VT_MAP: if (lIsContainer) outEndl(pCtx);; break;
			case VT_STRUCT: case VT_ANY: { pCtx.os() << "</"; outURIID(pCtx, pValue.getPropID()); pCtx.os() << ">"; outEndl(pCtx); break; }
			default: { pCtx.os() << "</afyxml:element>"; outEndl(pCtx); break; }
		}

		pCtx.mLevel--;
	}

	inline Value const * PrimitivesOutXml::findValueOf(ContextOutXml & pCtx, Value const & pParent, ContextOutXml::eImportConvention pType)
	{
		if (!pCtx.mImportConvention)
			return NULL;
		if (VT_COLLECTION != pParent.type && VT_STRUCT != pParent.type)
			return NULL;
		CollectionIterator lCI(pParent);
		for (Value const * iV = lCI.beginAtIndex(0); iV; iV = lCI.next())
			if (pCtx.mImportConvention[pType].uid == iV->property)
				return iV;
		return NULL;
	}

	inline Value const * PrimitivesOutXml::findValueOf(ContextOutXml & pCtx, IPIN const & pParent, ContextOutXml::eImportConvention pType)
	{
		if (!pCtx.mImportConvention)
			return NULL;
		return pParent.getValue(pCtx.mImportConvention[pType].uid);
	}

	inline void PrimitivesOutXml::renderAttributes(ContextOutXml & pCtx, Value const * pStruct)
	{
		if (!pStruct || VT_STRUCT != pStruct->type)
			return;
		CollectionIterator lCI(*pStruct);
		for (Value const * iV = lCI.beginAtIndex(0); iV; iV = lCI.next())
		{
			if (iV->type != VT_STRING)
				continue; // Review
			pCtx.os() << " ";
			outURIID(pCtx, iV->getPropID());
			pCtx.os() << "=\"";
			outString(pCtx, iV->str, iV->length);
			pCtx.os() << "\"";
		}
	}
};

#endif
