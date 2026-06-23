// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2019-2024 Second State INC

//===-- wasmedge/executor/component/resource_builtins.h ------------------===//
//
// Part of the WasmEdge Project.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Synthesized core wasm functions backing the canonical ABI resource
/// built-ins `resource.new` / `resource.drop` / `resource.rep`
/// (CanonicalABI.md, definitions.py `canon_resource_new/drop/rep`). Each is a
/// HostFunctionBase whose run() manipulates the owning component instance's
/// resource handle table.
///
//===----------------------------------------------------------------------===//
#pragma once

#include "ast/component/type.h"
#include "runtime/hostfunc.h"
#include "runtime/instance/component/component.h"

namespace WasmEdge {
namespace Executor {

class Executor;

/// Which resource built-in a CanonResourceHostFunc implements.
enum class ResourceOp { New, Drop, Rep };

class CanonResourceHostFunc : public Runtime::HostFunctionBase {
public:
  /// `ResType` is the resolved resource `DefType *` (the runtime type
  /// identity); `CompInst` is the instance whose handle table this built-in
  /// operates on. `Exec` is only needed for `Drop` (to invoke the destructor);
  /// pass nullptr for New/Rep.
  CanonResourceHostFunc(
      Executor *Exec, ResourceOp Op, const AST::Component::DefType *ResType,
      const Runtime::Instance::ComponentInstance *CompInst) noexcept;

  Expect<void> run(const Runtime::CallingFrame &Frame,
                   Span<const ValVariant> Args, Span<ValVariant> Rets) override;

private:
  Executor *Exec;
  ResourceOp Op;
  const AST::Component::DefType *ResType;
  const Runtime::Instance::ComponentInstance *CompInst;
};

} // namespace Executor
} // namespace WasmEdge
