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

#include <affinity.h>
#include <startup.h>
#include <afysync.h>
#include <string>
using namespace Afy;

// Name the service.
#define VDEVSERVICE_NAME AFFINITY_SERVICE_PREFIX "VDEV"
#define VERBOSE_DEBUGGING 0

namespace VDEV
{
	/**
	 * Define the properties used to configure the service.
	 */
	enum ePropIndex
	{
		kPISTART = 0,
		kPIReadEvaluator = kPISTART,
		kPIReadUnits,
		kPIReadProperty,
		kPIWritePIN,
		kPIWriteProperty,
		kPIEvaluationParameters,
		// ---
		kPISpecialFunction,
		kPISF_stddev,
		kPISF_mean,
		kPITOTAL
	};
	enum eSpecialFunctions
	{
		kSFrandom = 10, // VDEVSPECIALFUNC#random enum.
		kSFrandomGaussian = 20, // VDEVSPECIALFUNC#randomGaussian enum.
	};
	static char const * sProps[] =
	{
		VDEVSERVICE_NAME "/read/evaluator", // Could be a simple expression, or a VT_STRUCT of named expressions.
		VDEVSERVICE_NAME "/read/units", // Should follow the structure chosen for read/evaluator.
		VDEVSERVICE_NAME "/read/property", // The default property name produced when reading.
		VDEVSERVICE_NAME "/write/pin", // Reference to a pin where to write the write/property (workaround for syntactic limitations with VT_REF* in pathSQL, and restricted access to the service PIN in affinity.h).
		VDEVSERVICE_NAME "/write/property", // Either a reference to a single property (that could contain a VT_STRUCT), or a property name.
		VDEVSERVICE_NAME "/evaluation/parameters", // Reference to a pin from which to obtain external parameters for evaluation.
		// ---
		VDEVSERVICE_NAME "/special/function", // Unrelated with the rest of VDEV... VDEVSPECIALFUNC#xxx user-defined functions, before they become available...
		VDEVSERVICE_NAME "/stddev", // Unrelated with the rest of VDEV... name of a parameter for VDEVSPECIALFUNC#randomGaussian.
		VDEVSERVICE_NAME "/mean", // Unrelated with the rest of VDEV... name of a parameter for VDEVSPECIALFUNC#randomGaussian.
	};

	#define PROVIDE_LISTENER_FLAVOR 1

	/**
	 * CollectionIterator
	 */
	class CollectionIterator
	{
		protected:
			Value const & mCollection;
			unsigned long mI; // Note: May not be defined.
			ElementID mCurr;
		public:
			CollectionIterator(Value const & pCollection) : mCollection(pCollection), mI((unsigned long)-1), mCurr(STORE_COLLECTION_ID) {}
			inline Value const * beginAtIndex(unsigned long pIndex);
			inline Value const * next();
			inline Value const * previous();
			inline void reset();
		private:
			CollectionIterator(CollectionIterator const &);
			CollectionIterator & operator =(CollectionIterator const &);
	};
	inline Value const * CollectionIterator::beginAtIndex(unsigned long pIndex)
	{
		reset();
		Value const * lV;
		if (mCollection.type==Afy::VT_COLLECTION || mCollection.type==Afy::VT_STRUCT)
		{
			if (mCollection.type==Afy::VT_STRUCT || !mCollection.isNav())
			{
				for (mI = 0; mI < pIndex && mI < mCollection.length; mI++);
				mCurr = (mI < mCollection.length) ? mCollection.varray[mI].eid : STORE_COLLECTION_ID;
				return (mI < mCollection.length) ? &mCollection.varray[mI] : NULL;
			}
			else
			{
				for (lV = mCollection.nav->navigate(GO_FIRST), mI = 0; mI < pIndex && lV; lV = mCollection.nav->navigate(GO_NEXT), mI++);
				mCurr = lV ? lV->eid : STORE_COLLECTION_ID;
				return lV;
			}
		}
		if (0 == pIndex)
			{ mI = 0; mCurr = mCollection.eid; return &mCollection; }
		return NULL;
	}
	inline Value const * CollectionIterator::next()
	{
		if ((unsigned long)-1 == mI || STORE_COLLECTION_ID == mCurr)
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
				mCurr = lV ? lV->eid : STORE_COLLECTION_ID;
				return lV;
			}
		}
		return NULL;
	}
	inline void CollectionIterator::reset()
	{
		mI = (unsigned long)-1;
		mCurr = STORE_COLLECTION_ID;
	}
};
using namespace VDEV;

/**
 * Implement the service.
 */
class VDEVService : public IService
{
	protected:
		/**
		 * Implement the processor.
		 * Note:
		 *   By specifying ISRV_NOCACHE in VDEVService::create,
		 *   we request that this be instantiated at every request performed on an instance
		 *   of the service.  This may not be optimal, but we favor simplicity and
		 *   readability in this case.
		 * Note:
		 *   Since this service is intended to demonstrate typical interactions with
		 *   hardware such as sensors and actuators, it could be that some instances
		 *   will be configured to only read, or only write.  Should an instance
		 *   be implemented to read and write, it's up to the creator of an instance to
		 *   make the "read/evaluator" conform with the "write/property" (e.g. by
		 *   using a property of the service PIN itself, and by reading the same property
		 *   that is written).
		 */
		class VDEVServiceProc : public IService::Processor
		{
			protected:
				VDEVService & mService; // Back-reference to the service.
				IAffinity * mCtx; // Store context.
				Value const * mWritePIN; // Reference to the PIN on which to update mWriteProperty (workaround).
				Value const * mWriteProperty; // Reference to the property to be updated, if the service is written (could be on another PIN).
				Value const * mReadEvaluator; // Evaluator expression to be used to produce an output value, if the service is read.
				Value const * mReadUnits; // Units of measurement to be applied to the output value, if the service is read.
				Value const * mEvalParamsPIN; // Reference to a PIN providing external parameters for evaluators (see the long explanation in doRead).
				Value const * mSpecialFunc; // VDEVSPECIALFUNC#xxx enum value (optional).
				bool const mIsEndpoint; // Whether or not this instance is used as an endpoint (i.e. polled, as opposed to being a LISTENER).
				bool mDone; // Internal state controlling how many PINs are produced when the service is an ENDPOINT, during SELECT.
			public:
				VDEVServiceProc(VDEVService & pService, IServiceCtx * pCtx, bool pIsEndpoint)
					: mService(pService)
					, mCtx(pCtx->getSession()->getAffinity())
					, mWriteProperty(NULL)
					, mReadEvaluator(NULL)
					, mReadUnits(NULL)
					, mIsEndpoint(pIsEndpoint)
					, mDone(false)
				{
					report(AfyRC::MSG_DEBUG, "VDEVServiceProc::VDEVServiceProc(%p)\n", this);
				}
				virtual ~VDEVServiceProc()
				{
					report(AfyRC::MSG_DEBUG, "VDEVServiceProc::~VDEVServiceProc(%p)\n", this);
					// Review: Not called? Leak?
				}
				virtual void cleanup(IServiceCtx *, bool)
				{
					report(AfyRC::MSG_DEBUG, "VDEVServiceProc::cleanup(%p)\n", this);
				}
			public:
				virtual RC invoke(IServiceCtx * pCtx, const Value & pIn, Value & pOut, unsigned & pMode)
				{
					// The general principle of 'invoke' is to produce a unit of output (pOut) per call.
					// Depending on the function it assumes in the service stack where it's used,
					// and on the way the service stack is invoked (via either SELECT or UPDATE),
					// a processor (i.e. 'this') will be invoked either for reading (i.e. with ISRV_READ
					// set by the framework in pMode) or writing (ISRV_WRITE).  In some service stack
					// configurations, where the processor ('this') acts as a filter, the production
					// of output is dependent upon input values (pIn), produced by a previous
					// service in the stack.  pIn and pOut allow for great freedom in terms of
					// in/out formats (e.g. raw bytes, Values, PINs etc.).  The infrastructure takes care
					// of optimizing the most common memory allocation patterns involved in
					// enveloping/growing/shrinking the payload along a service stack.
					// A processor ('this') decides how many units it needs to produce per input
					// (or globally per processor instance), by setting control bits on pMode.
					// One such control bit is ISRV_MOREOUT. The service infrastructure operates in an
					// either-or manner with ISRV_MOREOUT: while it's set by a processor, no additional
					// input is given to it.  In some cases a processor may not be able to produce output
					// until more input is available; the processor should then set ISRV_NEEDMORE.
					// Should a processor also specify ISRV_APPEND, the framework will keep growing
					// the input buffers on behalf of that processor (DOM-like processing).  In other cases,
					// a processor may need several 'invoke' calls to produce all desired
					// outputs for a given input, and may require to be provided the same input
					// repeatedly by the framework, in which case it can specify ISRV_KEEPINP.
					// A writing processor (ISRV_WRITE) may need to terminate its output with some
					// closing elements, in which case it can tell the framework to call it one last
					// time beyond last available input, by specifying ISRV_NEEDFLUSH; its 'invoke'
					// method will be called one last time with ISRV_EOM set.
					// pCtx also provides means for different services to communicate with each other,
					// e.g. via its ctx PIN.  When it's finished processing everything, a processor
					// should return RC_EOF.

					if (mDone)
						{ pMode &= ~ISRV_MOREOUT; pOut.setEmpty(); return RC_EOF; }

					report(AfyRC::MSG_DEBUG, "VDEVServiceProc::invoke(%p)\n", this);
					readServiceConfig(pCtx);
					RC lRC = RC_OK;
					if (0 != (pMode & ISRV_READ))
						lRC = doRead(pCtx, pIn, pOut, pMode);
					else if (0 != (pMode & ISRV_WRITE))
						lRC = doWrite(pCtx, pIn, pOut, pMode);

					mDone = true; // This service only ever returns 1 PIN per request.
					return lRC;
				}
			protected:
				RC doWrite(IServiceCtx * pCtx, const Value & pIn, Value & pOut, unsigned & pMode)
				{
					report(AfyRC::MSG_DEBUG, "VDEVServiceProc::doWrite(%p)\n", this);
					pMode &= ~ISRV_MOREOUT;
					pOut.setEmpty();
					if (mWriteProperty)
					{
						// Simply set the value specified by pIn (i.e. afy:content) on the property designated by mWriteProperty.
						Value lV = pIn;
						lV.op = OP_SET;
						URIID lWPropURIID = STORE_INVALID_URIID;
						switch (mWriteProperty->type)
						{
							// Note:
							//   All the VT_REF* flavors are +/- unusable at the moment, due to
							//   limitations in pathSQL for setting up a property as a reference to
							//   another property.  The VT_URIID/VT_STRING flavors do work.

							case VT_REFPROP:
							case VT_REFELT:
								lV.setPropID(mWriteProperty->ref.pid);
								if (mWriteProperty->ref.pin && RC_OK != mWriteProperty->ref.pin->modify(&lV, 1, MODE_COPY_VALUES))
									report(AfyRC::MSG_WARNING, "VDEVServiceProc::doWrite:%d(%p) - Failed to modify mWriteProperty\n", __LINE__, this);
								break;

							case VT_REFIDPROP:
							case VT_REFIDELT:
							{
								IPIN * lToModify = pCtx->getSession()->getPIN(mWriteProperty->refId->id);
								if (lToModify)
								{
									lV.setPropID(mWriteProperty->refId->pid);
									if (RC_OK != lToModify->modify(&lV, 1, MODE_COPY_VALUES))
										report(AfyRC::MSG_WARNING, "VDEVServiceProc::doWrite:%d(%p) - Failed to modify mWriteProperty\n", __LINE__, this);
									lToModify->destroy();
								}
								break;
							}

							case VT_STRING:
							{
								URIMap lURIMap;
								lURIMap.URI = mWriteProperty->str;
								lURIMap.uid = STORE_INVALID_URIID;
								if (RC_OK != pCtx->getSession()->mapURIs(1, &lURIMap))
									report(AfyRC::MSG_WARNING, "VDEVServiceProc::doWrite:%d(%p) - Failed to map %s\n", __LINE__, this, lURIMap.URI);
								else
									lWPropURIID = lURIMap.uid;
								break;
							}
							case VT_URIID:
								lWPropURIID = mWriteProperty->uid;
								break;

							default:
								report(AfyRC::MSG_WARNING, "VDEVServiceProc::doWrite:%d(%p) - Unexpected type for mWriteProperty: %d\n", __LINE__, this, mWriteProperty->type);
								break;
						}
						if (STORE_INVALID_URIID != lWPropURIID)
						{
							IPIN * lPIN = (mWritePIN->type == VT_REF) ? mWritePIN->ref.pin : pCtx->getSession()->getPIN(mWritePIN->id);
							lV.setPropID(lWPropURIID);
							if (RC_OK != lPIN->modify(&lV, 1, MODE_COPY_VALUES | MODE_RAW))
								report(AfyRC::MSG_WARNING, "VDEVServiceProc::doWrite:%d(%p) - Failed to modify mWriteProperty=%d\n", __LINE__, this, lWPropURIID);
							if (mWritePIN->type != VT_REF)
								lPIN->destroy();
						}
					}
					return RC_OK;
				}
			protected:
				RC doRead(IServiceCtx * pCtx, const Value & pIn, Value & pOut, unsigned & pMode)
				{
					report(AfyRC::MSG_DEBUG, "VDEVServiceProc::doRead(%p)\n", this);
					if (!pOut.isEmpty() || 0 != (pMode & (ISRV_WRITE|ISRV_FLUSH))) return RC_INVPARAM;
					pMode &= ~ISRV_MOREOUT;
					pOut.setEmpty();

					RC lRC = RC_EOF;
					IPIN * const lEvalParamsPIN = mEvalParamsPIN ? ((mEvalParamsPIN->type == VT_REF) ? mEvalParamsPIN->ref.pin : pCtx->getSession()->getPIN(mEvalParamsPIN->id)) : NULL;
					if (mSpecialFunc)
					{
						// User-defined functions.
						switch (mSpecialFunc->enu.eltid)
						{
							case kSFrandom:
								pOut.set((double)rand() / RAND_MAX);
								pOut.setPropID(mService.mProps[kPIReadProperty].uid);
								lRC = RC_OK;
								break;
							
							case kSFrandomGaussian:
							{
								double lR = ((2.0 * (double)rand() / RAND_MAX) - 1.0) + ((2.0 * (double)rand() / RAND_MAX) - 1.0) + ((2.0 * (double)rand() / RAND_MAX) - 1.0);
								double lStddev = 1.0, lMean = 0.0;
								if (lEvalParamsPIN)
								{
									Value const * lStddevV = lEvalParamsPIN->getValue(mService.mProps[kPISF_stddev].uid);
									Value const * lMeanV = lEvalParamsPIN->getValue(mService.mProps[kPISF_mean].uid);
									if (lStddevV && VT_DOUBLE == lStddevV->type)
										lStddev = lStddevV->d;
									if (lMeanV && VT_DOUBLE == lMeanV->type)
										lMean = lMeanV->d;
								}
								pOut.set(lR * lStddev + lMean);
								pOut.setPropID(mService.mProps[kPIReadProperty].uid);
								lRC = RC_OK;
								break;
							}

							default:
								assert(false);
								break;
						}
					}
					else if (mReadEvaluator)
					{
						Value * lEv = NULL;
						uint32_t iE;

						// Prepare a few parameters.
						// In a typical service interacting with real hardware, this is where
						// the hardware-generated samples would be obtained. Here, for demonstration
						// purposes, we provide 3 random values to the evaluator (reachable with :0, :1, :2).
						Value * lParams = NULL;
						unsigned lNumParams = 0;
						#if 1
							lNumParams = 3;
							lParams = (Value *)alloca(lNumParams * sizeof(Value));
							for (unsigned iParam = 0; iParam < lNumParams; iParam++)
								lParams[iParam].set(rand());
						#endif

						// Evaluate and produce the expected output.
						// The general approach here is to let the service be completely
						// unaware of the specifics of evaluation (this is left to the pathSQL
						// program using the service, as yet another parameter of configuration).
						// This is a typical requirement for any sensor/actuator general access protocol,
						// because the actual bytes produced by those sensors are typically not interpreted
						// by those protocols.
						//
						// To help workaround various limitations expressed below, we
						// accept multiple types of evaluators.
						//
						// TODO: review/reduce/rationalize, if and when the limitations below evolve.
						//
						// Note about VT_STRUCT:
						//   VT_STRUCT is supported here simply as a means to let arbitrary output
						//   structures be defined outside the service (in CPIN), and applied by
						//   the service.
						//
						// Note about VT_COLLECTION:
						//   VT_COLLECTION is supported with a slightly different intent than VT_STRUCT.
						//   Here, we essentially mimic the behavior of the kernel for actions such as
						//   afy:onEnter of a class.  The last statement only produces the output
						//   (similar to a relatively common convention, such as progn in LISP for example).
						//
						// Note about VT_EXPR:
						//   Presently IExpr::execute does not accept an evaluation context.
						//   The expression itself does not know the relationship between the property
						//   that holds it, and its owning PIN.  Also, it's not possible to provide
						//   such context explicitly via a parameter referring to a PIN (e.g. in :0),
						//   since expressions can't evaluate ':0.property', at the moment.  Therefore,
						//   IExpr::execute cannot evaluate any expression that refers to other
						//   properties of the PIN.  OTOH, on the positive side, IExpr is easy
						//   to use in combination with VT_STRUCT, which is great to describe the
						//   structure a complex output.
						//
						// Note about VT_STMT:
						//   Presently IStmt cannot be told externally how to interpret @self or @ctx.
						//   OTOH statements, unlike expressions, do know how to evaluate ':0.property'
						//   (or 'property FROM :0').  It's still impossible to evaluate fields of
						//   a VT_STRUCT in pathSQL at the moment, however.
						//   Here we reserve :0 to point to VDEV:"evaluation/parameters".
						//
						// Note about VT_STRING:
						//   An alternative would be to accept statements expressed as plain strings,
						//   and parse&run them here (possibly after performing some substitutions).
						//   For the moment I prefer avoiding this, although this approach could
						//   provide maximum control.
						//   
						// Note about access to the CPIN:
						//   Accessing parameters on the CPIN itself, from a statement, from here
						//   (IService::Processor::invoke), does not appear to be easy or encouraged
						//   (on one hand, we're given no direct access to that PIN, except via getParameter;
						//   on the other hand, it would need to be accessed as RAW, which complicates
						//   statements).  Hence, our VDEV:"evaluation/parameters" pin.
						//
						// Note about other solutions:
						//   It will soon be possible to define functions in services, accessible in pathSQL.
						//   While this will augment expressiveness, it does not solve the problem of
						//   general-purpose, externally-defined evaluators.
						//   Yet another approach could be to produce the raw bytes and let classes
						//   process them; this will always remain an option, but less appealing in the
						//   context of VDEV.
						lRC = RC_OK;
						ICursor * lCursor = NULL;
						#if VERBOSE_DEBUGGING
							printf("evaluator type: %d\n", mReadEvaluator->type);
							printf("evaluator parameter pin: %p [%llx]\n", lEvalParamsPIN, lEvalParamsPIN ? lEvalParamsPIN->getPID().pid : 0);
						#endif
						switch (mReadEvaluator->type)
						{
							case VT_EXPR:
								lEv = (Value *)pCtx->getResAlloc()->createValues(1); // Note: Consumed by createPIN.
								lEv->setEmpty();
								if (RC_OK != (lRC = mReadEvaluator->expr->execute(*lEv, lParams, lNumParams)))
									report(AfyRC::MSG_DEBUG, "VDEVServiceProc::doRead:%d(%p) - Failed evaluation with RC=%d\n", __LINE__, this, lRC);
								else
								{
									lEv->setPropID(mService.mProps[kPIReadProperty].uid);
									if (mReadUnits && Un_NDIM != mReadUnits->qval.units)
										lEv->qval.units = mReadUnits->qval.units;
									pOut.op = OP_ADD; // Note: Must be done before createPIN...
									if (RC_OK != (lRC = pCtx->getResAlloc()->createPIN(pOut, lEv, 1)))
										report(AfyRC::MSG_DEBUG, "VDEVServiceProc::doRead:%d(%p) - Failed creating output PIN, with RC=%d\n", __LINE__, this, lRC);
								}
								break;

							case VT_STMT:
								lEv = (Value *)pCtx->getResAlloc()->createValues(1); // Note: Consumed by createPIN.
								if (RC_OK != (lRC = evaluateStmt(pCtx, mReadEvaluator->stmt, *lEv, lEvalParamsPIN, lParams, lNumParams)))
									report(AfyRC::MSG_DEBUG, "VDEVServiceProc::doRead:%d(%p) - Failed evaluation with RC=%d\n", __LINE__, this, lRC);
								else
								{
									pOut.op = OP_ADD; // Note: Must be done before createPIN...
									if (RC_OK != (lRC = pCtx->getResAlloc()->createPIN(pOut, lEv, 1)))
										report(AfyRC::MSG_DEBUG, "VDEVServiceProc::doRead:%d(%p) - Failed creating output PIN, with RC=%d\n", __LINE__, this, lRC);
									#if VERBOSE_DEBUGGING
										else report(AfyRC::MSG_DEBUG, "=== evaluation of VT_STMT produced value: {property=%d, type=%d}\n", pOut.property, pOut.type);
									#endif
								}
								break;

							case VT_STRUCT:
								lEv = (Value *)pCtx->getResAlloc()->createValues(mReadEvaluator->length); // Note: Consumed by createPIN.
								for (lRC = RC_OK, iE = 0; iE < mReadEvaluator->length && RC_OK == lRC; iE++)
								{
									lEv[iE].setEmpty();
									switch (mReadEvaluator->varray[iE].type)
									{
										case VT_EXPR:
											if (RC_OK != (lRC = mReadEvaluator->varray[iE].expr->execute(lEv[iE], lParams, lNumParams)))
												report(AfyRC::MSG_DEBUG, "VDEVServiceProc::doRead:%d(%p) - Failed evaluation with RC=%d\n", __LINE__, this, lRC);
											break;
										case VT_STMT:
											if (RC_OK != (lRC = evaluateStmt(pCtx, mReadEvaluator->varray[iE].stmt, lEv[iE], lEvalParamsPIN, lParams, lNumParams)))
												report(AfyRC::MSG_DEBUG, "VDEVServiceProc::doRead:%d(%p) - Failed evaluation with RC=%d\n", __LINE__, this, lRC);
											break;
										default:
											// Review: Could accept constants for example...
											report(AfyRC::MSG_DEBUG, "VDEVServiceProc::doRead:%d(%p) - Unexpected type for subevaluator: %d\n", __LINE__, this, mReadEvaluator->varray[iE].type);
									}
									lEv[iE].setPropID(mReadEvaluator->varray[iE].property);
									if (mReadUnits && Un_NDIM != mReadUnits->varray[iE].qval.units)
										lEv[iE].qval.units = mReadUnits->varray[iE].qval.units;
								}
								pOut.op = OP_ADD; // Note: Must be done before createPIN...
								if (RC_OK == lRC && RC_OK != (lRC = pCtx->getResAlloc()->createPIN(pOut, lEv, mReadEvaluator->length)))
									report(AfyRC::MSG_DEBUG, "VDEVServiceProc::doRead:%d(%p) - Failed creating output PIN, with RC=%d\n", __LINE__, this, lRC);
								break;

							case VT_COLLECTION:
							{
								// Note: Here the convention we adopt is to produce only one output value; intermediate outputs, if any, are overwritten.
								lEv = (Value *)pCtx->getResAlloc()->createValues(1); // Note: Consumed by createPIN.
								CollectionIterator iC(*mReadEvaluator);
								Value const * iCv;
								int iStmt = 0;
								for (lRC = RC_OK, iCv = iC.beginAtIndex(0); NULL != iCv && RC_OK == lRC; iCv = iC.next(), iStmt++)
								{
									if (VT_STMT != iCv->type)
										{	lRC = RC_INVPARAM; report(AfyRC::MSG_DEBUG, "VDEVServiceProc::doRead:%d(%p) - Expected a statement, got VT=%d\n", __LINE__, this, iCv->type); break; }
									lRC = evaluateStmt(pCtx, iCv->stmt, *lEv, lEvalParamsPIN, lParams, lNumParams);
									if (RC_EOF == lRC)
										lRC = RC_OK;
									#if VERBOSE_DEBUGGING
										report(AfyRC::MSG_DEBUG, "=== evaluation of VT_COLLECTION element #%d produced RC=%d, value: {property=%d, type=%d}\n", iStmt, lRC, lEv->property, lEv->type);
									#endif
								}
								pOut.op = OP_ADD; // Note: Must be done before createPIN...
								if (RC_OK != (lRC = pCtx->getResAlloc()->createPIN(pOut, lEv, 1)))
									report(AfyRC::MSG_DEBUG, "VDEVServiceProc::doRead:%d(%p) - Failed creating output PIN, with RC=%d\n", __LINE__, this, lRC);
								break;
							}

							default:
								report(AfyRC::MSG_WARNING, "VDEVServiceProc::doRead:%d(%p) - Unexpected type for mReadEvaluator: %d\n", __LINE__, this, mReadEvaluator->type);
								break;
						}
						if (lCursor)
							lCursor->destroy();

						pOut.setPropID(mService.mProps[kPIReadProperty].uid);
					}
					if (lEvalParamsPIN && VT_REF != mEvalParamsPIN->type)
						lEvalParamsPIN->destroy();

					return lRC;
				}

			protected:
				RC evaluateStmt(IServiceCtx * pCtx, IStmt * pStmt, Value & pOutV, IPIN * pEvalParamsPIN, Value * pParams, unsigned pNumParams)
				{
					RC lRC;
					ICursor * lCursor = NULL;
					pOutV.setEmpty();
					if (pEvalParamsPIN)
						pParams[0].set(pEvalParamsPIN);
					if (RC_OK != (lRC = pStmt->execute(&lCursor, pParams, pNumParams)))
					{
						char * lStmtStr = pStmt->toString(); 
						report(AfyRC::MSG_DEBUG, "VDEVServiceProc::evaluateStmt(%p) - Failed evaluation of %s with RC=%d\n", this, lStmtStr, lRC);
						pCtx->getSession()->free(lStmtStr);
					}
					else if (RC_OK != (lRC = lCursor->next(pOutV)) && RC_EOF != lRC)
					{
						char * lStmtStr = pStmt->toString(); 
						report(AfyRC::MSG_DEBUG, "VDEVServiceProc::evaluateStmt(%p) - Failed result iteration of %s with RC=%d\n", this, lStmtStr, lRC);
						pCtx->getSession()->free(lStmtStr);
					}
					else
					{
						pOutV.setPropID(mService.mProps[kPIReadProperty].uid);
						if (mReadUnits && Un_NDIM != mReadUnits->qval.units)
							pOutV.qval.units = mReadUnits->qval.units;
					}
					if (lCursor)
						{ lCursor->destroy(); lCursor = NULL; }
					return lRC;
				}

			protected:
				void readServiceConfig(IServiceCtx * pCtx)
				{
					// Note:
					//   Since a new processor instance is created at every evaluation,
					//   this function will pick up the latest value for each of those properties,
					//   thus making it possible to reconfigure them on the fly, including
					//   for request-response-style interactions (until fully supported by the
					//   kernel with upcoming MERGE syntax).

					// Find out how this instance should read and write its values.
					mWritePIN = pCtx->getParameter(mService.mProps[kPIWritePIN].uid);
					mWriteProperty = pCtx->getParameter(mService.mProps[kPIWriteProperty].uid);
					mReadEvaluator = pCtx->getParameter(mService.mProps[kPIReadEvaluator].uid);
					mReadUnits = pCtx->getParameter(mService.mProps[kPIReadUnits].uid);
					mEvalParamsPIN = pCtx->getParameter(mService.mProps[kPIEvaluationParameters].uid);
					mSpecialFunc = pCtx->getParameter(mService.mProps[kPISpecialFunction].uid);

					// Perform some verifications on the specified configuration.
					// TODO: Also support VT_COLLECTION for these things? any assignment resulting from a (SELECT ...)
					//       is likely to result in a collection here...
					if (mWriteProperty)
					{
						// For the moment, the mWritePIN workaround is needed.
						if (!mWritePIN || (mWritePIN->type != VT_REF && mWritePIN->type != VT_REFID))
						{
								report(AfyRC::MSG_WARNING, "VDEVServiceProc::readServiceConfig:%d(%p) - Unexpected type for %s : %d", __LINE__, this, sProps[kPIWritePIN], mWritePIN ? mWritePIN->type : VT_ERROR);
								throw "Configuration Error";
						}
						switch (mWriteProperty->type)
						{
							case VT_REFPROP:
							case VT_REFIDPROP:
							case VT_REFELT:
							case VT_REFIDELT:
							case VT_STRING:
							case VT_URIID:
								break;
							default:
								report(AfyRC::MSG_WARNING, "VDEVServiceProc::readServiceConfig:%d(%p) - Unexpected type for %s : %d", __LINE__, this, sProps[kPIWriteProperty], mWriteProperty->type);
								throw "Configuration Error";
						}
					}
					if (mReadEvaluator)
					{
						if (VT_STMT != mReadEvaluator->type && VT_EXPR != mReadEvaluator->type && VT_STRUCT != mReadEvaluator->type && VT_COLLECTION != mReadEvaluator->type)
						{
							report(AfyRC::MSG_WARNING, "VDEVServiceProc::readServiceConfig:%d(%p) - Unexpected type for %s : %d", __LINE__, this, sProps[kPIReadEvaluator], mReadEvaluator->type);
							throw "Configuration Error";
						}
					}
					if (mReadUnits)
					{
						if (!mReadEvaluator ||
							(mReadEvaluator->type == VT_STRUCT && ((mReadUnits->type != VT_STRUCT) || (mReadUnits->length != mReadEvaluator->length))) ||
							(mReadEvaluator->type == VT_EXPR && !isNumeric(ValueType(mReadUnits->type))) ||
							(mReadEvaluator->type == VT_STMT && mReadUnits->type == VT_STRUCT) ||
							(mReadEvaluator->type == VT_COLLECTION && (mReadUnits->type == VT_STRUCT || mReadUnits->type == VT_COLLECTION)))
						{
							report(AfyRC::MSG_WARNING, "VDEVServiceProc::readServiceConfig:%d(%p) - Unexpected configuration for %s", __LINE__, this, sProps[kPIReadUnits]);
							throw "Configuration Error";
						}
					}
					if (mEvalParamsPIN && (mEvalParamsPIN->type != VT_REF && mEvalParamsPIN->type != VT_REFID))
					{
						report(AfyRC::MSG_WARNING, "VDEVServiceProc::readServiceConfig:%d(%p) - Unexpected type for %s", __LINE__, this, sProps[kPIEvaluationParameters], mEvalParamsPIN->type);
						throw "Configuration Error";
					}
					if (mSpecialFunc)
					{
						if ((mWritePIN || mWriteProperty || mReadEvaluator) ||
							VT_ENUM != mSpecialFunc->type ||
							mSpecialFunc->enu.enumid != mService.mEnums[0].uid)
						{
							report(AfyRC::MSG_WARNING, "VDEVServiceProc::readServiceConfig:%d(%p) - Misuse of %s", __LINE__, this, sProps[kPISpecialFunction]);
							throw "Configuration Error";
						}
					}
				}
		};
		friend class VDEVServiceProc;
	protected:

		#if PROVIDE_LISTENER_FLAVOR
			/**
			 * Also implement a listener,
			 * for cases where the service will be used as an active emitter of samples
			 * (with afy:listen instead of afy:service).  This demonstrates inbound
			 * notification/interrupt-based sample collection, such as what
			 * occurs with BLE notifications, and provides the ability to attach
			 * a service stack to process those samples (before they are passed on
			 * in their proper semantic form to general-purpose PIN/message-handling,
			 * done in pathSQL applications via their classes, FSMs etc.).
			 */
			class VDEVListener : public IListener
			{
				protected:
					VDEVService & mService; // Back-reference to the service.
					IAffinity * mAfyCtx;
					ISession * mSession;
					VDEVServiceProc * mProc;
					HTHREAD mThread;
					long volatile mStop;
					URIID const mURIID;
					Value * mServiceParams;
					unsigned const mNumServiceParams;
				public:
					VDEVListener(VDEVService & pService, IAffinity * pAfyCtx, URIID pURIID, ISession * pSession, Value const * pParams, unsigned pNumParams)
						: mService(pService)
						, mAfyCtx(pAfyCtx)
						, mSession(pSession)
						, mProc(NULL)
						, mThread(NULL)
						, mStop(0)
						, mURIID(pURIID)
						, mServiceParams(NULL)
						, mNumServiceParams(pNumParams)
					{
						report(AfyRC::MSG_DEBUG, "VDEVListener::VDEVListener(%p)\n", this);
						if (mNumServiceParams > 0 && RC_OK != pSession->copyValues(pParams, mNumServiceParams, mServiceParams))
							report(AfyRC::MSG_WARNING, "VDEVListener::VDEVListener(%p) - Failed to copy service parameters\n", this);
						createThread(sThreadProc, this, mThread); // Review: at least document the implications in terms of number of threads created...
					}
					virtual ~VDEVListener()
					{
						report(AfyRC::MSG_DEBUG, "VDEVListener::~VDEVListener(%p)\n", this);
						if (mServiceParams)
						{
							mSession->freeValues(mServiceParams, mNumServiceParams);
							mServiceParams = NULL;
						}
						// TODO: release mProc etc.
					}
					virtual IService * getService() const { return &mService; }
					virtual URIID getID() const { return mURIID; }
					virtual RC create(IServiceCtx * pCtx, uint32_t&, IService::Processor *& pRet)
					{
						report(AfyRC::MSG_DEBUG, "VDEVListener::create(%p)\n", this);
						try { pRet = mProc = new(pCtx) VDEVServiceProc(mService, pCtx, false); }
						catch (...) { report(AfyRC::MSG_WARNING, "VDEVListener::create(%p) - An exception aborted this evaluation", this); }
						return RC_OK;
					}
					virtual RC stop(bool fSuspend)
					{
						report(AfyRC::MSG_DEBUG, "VDEVListener::stop(%p)\n", this);
						if (mThread)
						{
							InterlockedIncrement(&mStop);
							threadsWaitFor(1, &mThread);
							mThread = NULL;
						}
						return RC_OK;
					}
				protected:
					static THREAD_SIGNATURE sThreadProc(void *pThis){((VDEVListener *)pThis)->threadProc(); return 0;}
					void threadProc()
					{
						// Review: at least document implications in terms of number of threads/stores etc.
						report(AfyRC::MSG_DEBUG, "Starting VDEVListener's thread (%p)\n", this);
						ISession * lSession = mAfyCtx->startSession();
						if (NULL == lSession)
						{
							report(AfyRC::MSG_WARNING, "VDEVListener::threadProc(%p) - Failed to startSession\n", this);
							return;
						}

						RC lRC;
						IServiceCtx * lServiceCtx = NULL;
						while (!mStop)
						{
							if (RC_OK != (lRC = lSession->createServiceCtx(mServiceParams, mNumServiceParams, lServiceCtx, false, this)))
								report(AfyRC::MSG_ERROR, "VDEVListener::threadProc(%p) - Failed in ISession::createServiceCtx() (%d)\n", this, lRC);
							lServiceCtx->invoke(NULL, 0);
							if (lServiceCtx)
								lServiceCtx->destroy();
							lServiceCtx = NULL;

							// Note:
							//   While this could be made configurable, in the particular case of VDEV
							//   there's no point investing efforts on this, since the TIMER feature of Affinity is
							//   already infinitely more sophisticated, and there's nothing about VDEV notifications
							//   that can't be demonstrated by polling VDEV on a timer.  The VDEV listener is
							//   provided essentially as a working sample, to complement the documentation.
							threadSleep(1000);
						}
					}
			};
	#endif

	protected:
		URIMap const * mProps, * mEnums;
	public:
		VDEVService(URIMap * pProps, URIMap * pEnums) : mProps(pProps), mEnums(pEnums) {}
		virtual ~VDEVService() {}

		/**
		 * When the service is used as a passive ENDPOINT (or maybe eventually as a filter),
		 * VDEVService::create is called to produce an IService::Processor.
		 */
		virtual RC create(IServiceCtx * pCtx, uint32_t & pDscr, Processor *& pRet)
		{
			report(AfyRC::MSG_DEBUG, "VDEVService::create(%p)\n", this);
			switch ((pDscr & ISRV_PROC_MASK) &~ ISRV_ENDPOINT)
			{
				case ISRV_WRITE:
					pDscr |= ISRV_ALLOCBUF;
				case ISRV_READ:
					pDscr |= ISRV_NOCACHE; // Note: we cache our parameters internally, and also don't want to bother about internal state cleanups across invocations.
					try { pRet = new(pCtx) VDEVServiceProc(*this, pCtx, 0 != (pDscr & ISRV_ENDPOINT)); }
					catch (...) { report(AfyRC::MSG_WARNING, "VDEVService::create(%p) - An exception aborted this evaluation", this); }
					if (NULL == pRet)
						return RC_NOMEM;
					break;
				default:
					return RC_INVOP;
			}
			return RC_OK;
		}

		#if PROVIDE_LISTENER_FLAVOR
			/**
			 * When the service is used as an active LISTENER,
			 * VDEVService::listen is called to produce an IListener.
			 */
			virtual RC listen(ISession * pSes, URIID pURIID, const Value * pParams, unsigned nParams, const Value * srvParams, unsigned nSrvparams, unsigned mode, IListener *& pRet)
			{
				try { pRet = new VDEVListener(*this, pSes->getAffinity(), pURIID, pSes, pParams, nParams); } // Review: right allocator?
				catch (...) { report(AfyRC::MSG_WARNING, "VDEVService::listen(%p) - An exception aborted this listener", this); }
				return RC_OK;
			}
		#endif

	public:
		static URIMap * mapProperties(ISession * pSes, char const ** pNames, unsigned pNum, bool pObj=false)
		{
			IAffinity * const lCtx = pSes->getAffinity();
			URIMap * const lURIMap = (URIMap*)lCtx->malloc(pNum * sizeof(URIMap));
			if (!lURIMap) return NULL;
			unsigned i;
			for (i = 0; i < pNum; i++) { lURIMap[i].URI = pNames[i]; lURIMap[i].uid = STORE_INVALID_URIID; }
			if (RC_OK != pSes->mapURIs(pNum, lURIMap, NULL, pObj)) { lCtx->free(lURIMap); return NULL; }
			for (i = 0; i < pNum; i++) { printf("-- mapped prop %s to %d\n", lURIMap[i].URI, lURIMap[i].uid); }
			return lURIMap;
		}
};

extern "C" AFY_EXP bool SERVICE_INIT(VDEV)(ISession * pSes, const Value *, unsigned, bool pNew)
{
	// Retrieve the current store context from the specified session.
	IAffinity * lCtx = pSes->getAffinity();

	// Create our enumerations, if they're not already there.
	static char const * sEnums[] = {"VDEVSPECIALFUNC"};
	RC lRC;
	if (pNew)
	{
		Value lVenum[3]; int iE = 0;
		lVenum[iE].set(sEnums[0]); lVenum[iE].setPropID(PROP_SPEC_OBJID); iE++;
		lVenum[iE].set("random"); lVenum[iE].setPropID(PROP_SPEC_ENUM); lVenum[iE].op = OP_ADD; lVenum[iE].eid = kSFrandom; iE++;
		lVenum[iE].set("randomGaussian"); lVenum[iE].setPropID(PROP_SPEC_ENUM); lVenum[iE].op = OP_ADD; lVenum[iE].eid = kSFrandomGaussian; iE++;
		if (RC_OK != (lRC = pSes->createPIN(lVenum, iE, NULL, MODE_COPY_VALUES | MODE_PERSISTENT | MODE_FORCE_EIDS)) && RC_ALREADYEXISTS != lRC)
			report(AfyRC::MSG_WARNING, "VDEV: Failed to create SPECIALFUNC enum: RC=%d\n", lRC);
	}

	// Map all our URIIDs.
	URIMap * const lURIMap = VDEVService::mapProperties(pSes, sProps, sizeof(sProps) / sizeof(sProps[0]));
	URIMap * const lEnumURIMap = VDEVService::mapProperties(pSes, sEnums, 1, true);

	// Instantiate the service and acknowledge success.
	lCtx->registerPrefix("VDEV", 4, VDEVSERVICE_NAME "/", sizeof(VDEVSERVICE_NAME));
	VDEVService * lVDEV = new(lCtx) VDEVService(lURIMap, lEnumURIMap);
	return (NULL != lVDEV && RC_OK == lCtx->registerService(VDEVSERVICE_NAME, lVDEV));
}

/*
	-- load the service:
	CREATE LOADER _vdev AS 'VDEV';
	SET TRACE ALL COMMUNICATIONS;

	-- read-only passive (aka ENDPOINT) sensor setup:
	INSERT afy:objectID='temperature1', afy:service={.srv:VDEV}, VDEV:"read/evaluator"=$(5 + 10 * SIN(EXTRACT(FRACTIONAL FROM CURRENT_TIMESTAMP))), VDEV:"read/units"=0dC;
	INSERT afy:objectID='temperature2', afy:service={.srv:VDEV}, VDEV:"read/evaluator"=${SELECT _y0 + _yf * SIN(EXTRACT(FRACTIONAL FROM CURRENT_TIMESTAMP)) FROM :0}, VDEV:"read/units"=0dC, VDEV:"evaluation/parameters"=(INSERT _y0=10dC, _yf=5dC);
	INSERT afy:objectID='gps1', afy:service={.srv:VDEV}, VDEV:"read/evaluator"={x=$(5 + 6 * :0), y=$(5 + 6 * SIN(EXTRACT(SECOND FROM CURRENT_TIMESTAMP))), z=$(5 + 6 * SIN(EXTRACT(MINUTE FROM CURRENT_TIMESTAMP)))}, VDEV:"read/units"={x=0m, y=0m, z=0m};
	INSERT afy:objectID='gps2', afy:service={.srv:VDEV}, VDEV:"read/evaluator"={x=${SELECT _x0 + _xf * :1 FROM :0}, y=${SELECT _y0 + _yf * SIN(EXTRACT(SECOND FROM CURRENT_TIMESTAMP)) FROM :0}, z=${SELECT _z0 + _zf * SIN(EXTRACT(MINUTE FROM CURRENT_TIMESTAMP)) FROM :0}}, VDEV:"read/units"={x=0m, y=0m, z=0m}, VDEV:"evaluation/parameters"=(INSERT _x0=30m, _y0=30m, _z0=30m, _xf=10, _yf=10, _zf=10);

	-- read-only active (aka LISTENER) sensor setup:
	CREATE LISTENER temperature2 AS {.srv:VDEV, .srv:affinity} SET VDEV:"read/evaluator"={"body/temperature"=$(5 + 10 * SIN(EXTRACT(FRACTIONAL FROM CURRENT_TIMESTAMP)))}, VDEV:"read/units"={"body/temperature"=0dC};

	-- write-only (ENDPOINT) actuator setup:
	-- Note: I would have preferred using a VT_REF* type for VDEV/write/property, but those types of references are not well enough supported for the moment...
	INSERT afy:objectID='plainLED', afy:service={.srv:VDEV}, VDEV:"write/pin"=(INSERT _intensity=0), VDEV:"write/property"='_intensity';
	INSERT afy:objectID='rgbLED', afy:service={.srv:VDEV}, VDEV:write/pin"=(INSERT _color={r=0, g=0, b=0}), VDEV:"write/property"='_color';

	-- read-write (ENDPOINT) setup:
	INSERT afy:objectID='smartLED', afy:service={.srv:VDEV}, VDEV:"write/pin"=(INSERT _color={r=0, g=0, b=0}), VDEV:"write/property"='_color', VDEV:"read/evaluator"={r=$(VDEV:"write/pin"._color.r), g=$(VDEV:"write/pin"._color.g), b=$(VDEV:"write/pin"._color.b)};

	-- typical usage scenarios for the ENDPOINT cases:
	SELECT * FROM #temperature1;
	UPDATE #plainLED SET afy:content=32;
	UPDATE #smartLED SET afy:content={r=10, g=20, b=3};
	SELECT * FROM #smartLED;
	CREATE CLASS "air/monitor" AS SELECT * WHERE EXISTS("air/monitor/sample") SET
		afy:onEnter=${UPDATE @self SET "air/temperature"=(SELECT afy:value FROM #temperature1)};
	INSERT SELECT afy:value AS "air/monitor/sample" FROM @[1,50];

	-- typical usage scenarios for the LISTENER cases:
	INSERT afy:objectID=.stdout, afy:service={.srv:IO}, afy:address=1, qa:out=1;
	CREATE CLASS "body/monitor" AS SELECT * WHERE EXISTS("body/temperature") SET
		afy:onEnter=${UPDATE #stdout SET afy:content='Obtained body temperature reading: ' || @self."body/temperature"};

	-- embryo of the DAG scenario (works):
	INSERT afy:objectID='mydata';
	INSERT afy:service={.srv:VDEV}, afy:objectID='node1',
	VDEV:"read/evaluator"={
	 ${UPDATE #mydata SET lCache=(SELECT FIRST VDEV:"read/property" FROM :0)},
	 ${SELECT lCache & X'111111000000' FROM #mydata}},
	VDEV:"evaluation/parameters"=
	 (INSERT afy:service={.srv:VDEV}, afy:objectID='node2',
	 VDEV:"read/evaluator"=${SELECT "source/bits" FROM :0},
	 VDEV:"evaluation/parameters"=(INSERT "source/bits"=X'010101010101'));
*/

/*
	TODO: retest the listener mode
	TODO (later): true request-response, when syntax is ready (should not change much, will just get info via inp instead of @self).
	[TODO: investigate a filter mode also, as suggested by Ming but discouraged by Mark? later, if/when time allows...]
*/
