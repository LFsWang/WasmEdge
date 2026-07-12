// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2019-2024 Second State INC

#include "executor/component/resource_builtins.h"
#include "executor/executor.h"

#include "common/spdlog.h"

#include <array>
#include <cstdint>

namespace WasmEdge {
namespace Executor {

using namespace std::literals;
namespace Component = Runtime::Instance::Component;

CanonResourceHostFunc::CanonResourceHostFunc(
    Executor *ExecIn, ResourceOp OpIn, const AST::Component::DefType *ResTypeIn,
    const Runtime::Instance::ComponentInstance *CompInstIn) noexcept
    : HostFunctionBase(/*FuncCost=*/0), Exec(ExecIn), Op(OpIn),
      ResType(ResTypeIn), CompInst(CompInstIn) {
  // Synthesize the core signature: new [i32(rep)] -> [i32(handle)],
  // drop [i32(handle)] -> [], rep [i32(handle)] -> [i32(rep)]. These match the
  // shapes the validator synthesizes for the resource built-ins.
  auto &FT = DefType.getCompositeType().getFuncType();
  FT.getParamTypes().push_back(ValType(TypeCode::I32));
  if (Op != ResourceOp::Drop) {
    FT.getReturnTypes().push_back(ValType(TypeCode::I32));
  }
}

Expect<void> CanonResourceHostFunc::run(const Runtime::CallingFrame &,
                                        Span<const ValVariant> Args,
                                        Span<ValVariant> Rets) {
  // `may_leave` reentrance guards from the spec are not modeled (consistent
  // with the synchronous, non-reentrant executor); see the post-return TODO.
  auto &Table = CompInst->getResourceTable();
  const uint32_t Arg = Args[0].get<uint32_t>();

  switch (Op) {
  case ResourceOp::New: {
    // canon_resource_new: own handle to a fresh resource.
    Component::ResourceHandle H{};
    H.Rt = ResType;
    H.DefiningInst = CompInst;
    H.Rep = Arg;
    H.Own = true;
    EXPECTED_TRY(uint32_t Idx, Table.add(H));
    Rets[0] = ValVariant(Idx);
    return {};
  }
  case ResourceOp::Rep: {
    // canon_resource_rep: read the representation, keep the handle.
    EXPECTED_TRY(auto *H, Table.get(Arg));
    if (H->Rt != ResType) {
      spdlog::error(ErrCode::Value::ComponentTrap);
      spdlog::error("    canonical ABI: resource.rep type mismatch"sv);
      return Unexpect(ErrCode::Value::ComponentTrap);
    }
    Rets[0] = ValVariant(H->Rep);
    return {};
  }
  case ResourceOp::Drop: {
    // canon_resource_drop: validate the handle, then remove it, run the
    // destructor (own) or release the borrow (borrow). The traps are checked
    // via get() before remove() frees the slot: a still-lent handle
    // (NumLends != 0) must trap without being freed, otherwise the BorrowScope
    // lenders that still point at it would dangle. On a trap the whole call
    // unwinds, so leaving the handle in the table is unobservable and matches
    // the spec's remove-then-trap ordering.
    EXPECTED_TRY(auto *H, Table.get(Arg));
    if (H->Rt != ResType) {
      spdlog::error(ErrCode::Value::ComponentTrap);
      spdlog::error("    canonical ABI: resource.drop type mismatch"sv);
      return Unexpect(ErrCode::Value::ComponentTrap);
    }
    if (H->NumLends != 0) {
      spdlog::error(ErrCode::Value::ComponentTrap);
      spdlog::error("    canonical ABI: resource.drop of lent handle"sv);
      return Unexpect(ErrCode::Value::ComponentTrap);
    }
    EXPECTED_TRY(Component::ResourceHandle Removed, Table.remove(Arg));
    if (Removed.Own) {
      auto Dtor = ResType->getResourceType().getDestructor();
      if (Dtor.has_value()) {
        auto *DtorFn = Removed.DefiningInst->getCoreFunction(*Dtor);
        if (DtorFn == nullptr) {
          spdlog::error(ErrCode::Value::ComponentTrap);
          spdlog::error(
              "    canonical ABI: resource.drop destructor index out of range"sv);
          return Unexpect(ErrCode::Value::ComponentTrap);
        }
        std::array<ValVariant, 1> DArgs{ValVariant(Removed.Rep)};
        auto ParamTypes = DtorFn->getFuncType().getParamTypes();
        EXPECTED_TRY(Exec->invoke(DtorFn, DArgs, ParamTypes));
      }
    } else if (Removed.Scope != nullptr) {
      Removed.Scope->NumBorrows--;
    }
    return {};
  }
  default:
    assumingUnreachable();
  }
}

} // namespace Executor
} // namespace WasmEdge
