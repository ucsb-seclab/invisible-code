#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/ValueSymbolTable.h"
#include <llvm/Analysis/CallGraph.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Support/Debug.h>
#include <set>
#include "llvm/Support/FileSystem.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"


using namespace llvm;

namespace DRMCODE {

    static cl::opt<std::string> targetSecName("sec_name",
                                              cl::desc("Name of the section where all the secure code will be present."),
                                              cl::value_desc("ASCII Name of the section where all the secure code is supposed to be."),
                                              cl::init("invisible_code"));

    static cl::opt<std::string> cfiDataStore("cfi_data_store",
                                             cl::desc("Name of the symbol which is the entry point of all CFI data."),
                                             cl::value_desc("ASCII Name of the symbol, which is the entry point of all CFI data."),
                                             cl::init(""));

    static cl::opt<std::string> outputFile("outputFuncs",
                                           cl::desc("Path to the output file, where all the names of the secure "
                                                    "functions should be stored."),
                                           cl::value_desc("Path of the output file."), cl::init("secure_functions.txt"));


    struct IndirectCallCFIPass: public ModulePass {
    public:
        static char ID;
        //GlobalState moduleState;

        IndirectCallCFIPass() : ModulePass(ID) {
        }

        ~IndirectCallCFIPass() {
        }

        Value* getTargetGlobal(Module &m, std::string &globalName) {
            GlobalVariable *targetGlobal = m.getNamedGlobal(globalName);
            if(targetGlobal == nullptr) {
                for(auto mi=m.begin(), me=m.end(); mi != me; mi++) {
                    Function *currFunc = &(*mi);
                    if(!currFunc->isDeclaration() && currFunc->hasName() && globalName.compare(currFunc->getName()) == 0) {
                        return currFunc;
                    }
                }
            }
            return targetGlobal;
        }

        Value* getFunctionStore(Module &m) {
            std::string targetGlobalName = cfiDataStore;
            if(targetGlobalName.length() == 0) {
                targetGlobalName = "__stop_" + targetSecName;
            }
            Value *targetGlobal = getTargetGlobal(m, targetGlobalName);
            if(targetGlobal != nullptr) {
                dbgs() << "[+] Found the secure function table\n";
            } else {
                dbgs() << "[!] Unable to find symbol:" << targetGlobalName << ", where the "
                          "function addresses are supposed to be stored.\n";
            }
            return targetGlobal;
        }

        Value* getSecSectionStart(Module &m) {
            std::string targetGlobalName = "__start_" + targetSecName;
            GlobalVariable *targetGlobal = m.getNamedGlobal(targetGlobalName);
            if(targetGlobal != nullptr) {
                dbgs() << "[+] Found the secure section start.\n";
            } else {
                dbgs() << "[!] Unable to find symbol:" << targetGlobalName << ", where is "
                        "the start of the secure code section.\n";
            }
            return targetGlobal;
        }

        bool isSecureFunction(Function *targetFunc) {
            // check if the provided function is secure?
            if(!targetFunc->isDeclaration() && targetFunc->hasSection()) {
                std::string currSecName(targetFunc->getSection());
                return (currSecName.compare(targetSecName) == 0);
            }
            return false;
        }

        long getNumSecureFunctions(Module &m) {
            // get total number of secure functions
            // in the current module.
            long numFunc = 0;
            for(auto mi=m.begin(), me=m.end(); mi != me; mi++) {
                Function *currFunc = &*mi;
                if(isSecureFunction(currFunc)) {
                    numFunc++;
                }
            }
            return numFunc;
        }

        bool getAllIndirectInstructions(Function *currFunc, std::set<Instruction*> &targetInst) {
            // get all indirect all instructions in the given function.
            targetInst.clear();

            for(auto fi=currFunc->begin(), fe=currFunc->end(); fi != fe; fi++) {
                BasicBlock &currBB = *fi;
                for(auto bi=currBB.begin(), be=currBB.end(); bi != be; bi++) {
                    Instruction *currInstr = &(*bi);
                    CallInst *currCallInstr = dyn_cast<CallInst>(currInstr);
                    if(currCallInstr != nullptr && !currCallInstr->isInlineAsm()) {
                        Value *targetVal = currCallInstr->getCalledValue();
                        targetVal = targetVal->stripPointerCasts();
                        Function *targetFun = dyn_cast<Function>(targetVal);
                        if(targetFun == nullptr) {
                            // indirect function
                            targetInst.insert(currInstr);
                        }
                    }
                }
            }

            return !targetInst.empty();
        }

        bool instrumentFunction(Function *currFun, Module &m, Value *funcArgVal, Value *secStartSym, long numSecFunc) {

            bool retVal = false;
            std::set<Instruction*> targetIndirectCallInstrs;

            if(getAllIndirectInstructions(currFun, targetIndirectCallInstrs)) {
                retVal = true;
                Type* ptrType = Type::getInt64Ty(m.getContext());
                BasicBlock &currBB = currFun->getEntryBlock();
                IRBuilder<> IRB(currBB.getFirstNonPHIOrDbg());

                // initial setup
                //Value *currAlloca = IRB.CreateAlloca(Type::getInt64Ty(m.getContext()), nullptr, "numsecfunc");
                Value *idxinstr = IRB.CreateAlloca(Type::getInt64Ty(m.getContext()), nullptr, "secfuncidx");
                Constant *numSecFunConst = ConstantInt::get(ptrType, numSecFunc);
                // This is the start sec variable
                //Value *startSec = IRB.CreateAlloca(Type::getInt64Ty(m.getContext()), nullptr, "startsecnum");
                // This is the stop sec variable
                //Value *stopSec = IRB.CreateAlloca(Type::getInt64Ty(m.getContext()), nullptr, "stopsecnum");

                Value *startSecInt = IRB.CreatePtrToInt(secStartSym, ptrType);
                Value *stopSecInt = IRB.CreatePtrToInt(funcArgVal, ptrType);

                //IRB.CreateStore(startSecInt, startSec);
                //IRB.CreateStore(stopSecInt, stopSec);

                for(auto currIns: targetIndirectCallInstrs) {
                    // First get the function ptr.
                    CallInst* currCallInstr = dyn_cast<CallInst>(currIns);
                    BasicBlock *oldBB = currCallInstr->getParent();
                    Value *targetVal = currCallInstr->getCalledValue()->stripPointerCasts();

                    // split the BB at the indirect call instruction.
                    BasicBlock *newBB = currCallInstr->getParent()->splitBasicBlock(currCallInstr);

                    // where we actually check the array loop index..
                    // if the condition fails..we connect to a new basic block which just calls exit.
                    BasicBlock *checkBB = BasicBlock::Create(m.getContext(), "", currFun, newBB);
                    IRBuilder<> CheckInserter(checkBB);
                    Value *currIdx = CheckInserter.CreateLoad(idxinstr, "curridx");
                    Value *idxLessThenEq = CheckInserter.CreateICmpULE(currIdx, numSecFunConst);


                    // here just increment the index and go back to checkBB.
                    BasicBlock *loopIndexIncrement = BasicBlock::Create(m.getContext(), "", currFun, newBB);
                    IRBuilder<> LoopIncInserter(loopIndexIncrement);
                    Value *newVal = LoopIncInserter.CreateAdd(currIdx, ConstantInt::get(ptrType, 1));
                    LoopIncInserter.CreateStore(newVal, idxinstr);
                    LoopIncInserter.CreateBr(checkBB);

                    // here we get the element of the array and check against the func ptr.
                    // if yes, jump to new, else go to loop increment.
                    BasicBlock *indexBB = BasicBlock::Create(m.getContext(), "", currFun, newBB);


                    IRBuilder<> IndexBBInserter(indexBB);
                    Value* funcArray = IndexBBInserter.CreateIntToPtr(stopSecInt, Type::getInt64PtrTy(m.getContext()));
                    Value *newcurrIdx = IndexBBInserter.CreateLoad(idxinstr, "curridxnew");
                    Value *currIndxGEP = IndexBBInserter.CreateGEP(Type::getInt64Ty(m.getContext()), funcArray, newcurrIdx);
                    Value *currFuncVal = IndexBBInserter.CreateLoad(currIndxGEP);
                    Value *isMatch = IndexBBInserter.CreateICmpEQ(currFuncVal, IndexBBInserter.CreatePtrToInt(targetVal, ptrType));
                    IndexBBInserter.CreateCondBr(isMatch, newBB, loopIndexIncrement);

                    // Fill this with call to exit function.
                    BasicBlock *exitBB = BasicBlock::Create(m.getContext(), "CFIBammedUp", currFun, newBB);
                    IRBuilder<> ExitBBInserter(exitBB);
                    std::vector<Type*> paramTypes;
                    paramTypes.push_back(Type::getInt32Ty(m.getContext()));
                    //paramTypes[0] = Type::getInt32Ty(m.getContext());
                    FunctionType* exitFuncType = FunctionType::get(Type::getVoidTy(m.getContext()), paramTypes, false);
                    Constant *exitFuncPtr = m.getOrInsertFunction("exit", exitFuncType);
                    Instruction *targetBrInstr = ExitBBInserter.CreateBr(newBB);
                    std::vector<Value*> paramValues;
                    paramValues.push_back(ConstantInt::get(Type::getInt32Ty(m.getContext()), 1));
                    CallInst::Create(exitFuncPtr, paramValues, "", targetBrInstr);



                    CheckInserter.CreateCondBr(idxLessThenEq, indexBB, exitBB);


                    // the first check whether the func ptr is in between start and stop.
                    BasicBlock *firstCheck = BasicBlock::Create(m.getContext(), "", currFun, newBB);
                    IRBuilder<> FBInserter(firstCheck);
                    Value *callPtrInt = FBInserter.CreatePtrToInt(targetVal, ptrType);
                    Value *gtStart = FBInserter.CreateICmpUGE(callPtrInt, startSecInt);
                    Value *ltStop = FBInserter.CreateICmpULT(callPtrInt, stopSecInt);
                    Value *condAnd = FBInserter.CreateAnd(gtStart, ltStop);
                    Constant *zeroInt = ConstantInt::get(ptrType, 1);
                    FBInserter.CreateStore(zeroInt, idxinstr);
                    FBInserter.CreateCondBr(condAnd, checkBB, newBB);

                    //FBInserter.CreateBr(newBB);

                    //TODO: remove the terminator instruction and insert jump to firstCheck
                    // basic block

                    //oldBB->getTerminator()->removeFromParent();

                    Instruction *targetInstr = nullptr;

                    BranchInst *currBr = BranchInst::Create(firstCheck, targetInstr);
                    llvm::ReplaceInstWithInst(oldBB->getTerminator(), currBr);

                    //oldInstr->removeFromParent();
                    //IRBuilder<> OLDBBIN(oldBB);
                    //OLDBBIN.CreateBr(firstCheck);
                    //llvm::ReplaceInstWithInst(oldInstr, newJmp);



                }
            }

            return retVal;
        }



        bool runOnModule(Module &m) override {

            dbgs() << "[+] Starting CFI Instrumentation.\n";

            Value *functionTabStart = getFunctionStore(m);
            Value *secureSecStart = getSecSectionStart(m);
            std::set<Function*> secFunctions;
            long numSecFunc = getNumSecureFunctions(m);
            dbgs() << "[+] Number of secure functions:" << numSecFunc << "\n";
            for(auto mi=m.begin(), me=m.end(); mi != me; mi++) {
                Function *currFunc = &(*mi);
                if(isSecureFunction(currFunc)) {
                    secFunctions.insert(currFunc);
                    dbgs() << "[+] Trying to instrument function:" << currFunc->getName() << "\n";
                    if(instrumentFunction(currFunc, m, functionTabStart, secureSecStart, numSecFunc)) {
                        dbgs() << "[+] Instrumentation Successful for function:" << currFunc->getName() << "\n";
                    } else {
                        dbgs() << "[+] Instrumentation not needed for function:" << currFunc->getName() << "\n";
                    }
                }
            }

            dbgs() << "[+] Finished CFI Instrumentation.\n";

            std::error_code res_code;
            dbgs() << "[+] Writing all secure function names to:" << outputFile << "\n";
            llvm::raw_fd_ostream op_stream(outputFile, res_code, llvm::sys::fs::F_Text);
            for(auto a:secFunctions) {
                op_stream << a->getName() << "\n";
            }
            op_stream.close();
            dbgs() << "[+] Done writing function names.\n";

            return true;

        }

        void getAnalysisUsage(AnalysisUsage &AU) const override {
            AU.setPreservesAll();
            AU.addRequired<CallGraphWrapperPass>();
            AU.addRequired<LoopInfoWrapperPass>();
        }

    };

    char IndirectCallCFIPass::ID = 1;
    static RegisterPass<IndirectCallCFIPass> xx("drmcfi", "CFI Pass for DRM Code", false, false);
}