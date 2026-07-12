// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2019-2024 Second State INC

#include "executor/executor.h"

namespace WasmEdge {
namespace Executor {

Expect<void>
Executor::instantiate(Runtime::Instance::ComponentInstance &CompInst,
                      const AST::Component::CoreTypeSection &CoreTypeSec) {
  for (auto &Ty : CoreTypeSec.getContent()) {
    CompInst.addCoreType(Ty);
  }
  return {};
}

Expect<void>
Executor::instantiate(Runtime::Instance::ComponentInstance &CompInst,
                      const AST::Component::TypeSection &TypeSec) {
  for (auto &Ty : TypeSec.getContent()) {
    CompInst.addType(Ty);
    // A `(type (resource ...))` in this component's type section is a local
    // resource definition: this instance is the resource's defining instance
    // (the spec's `t.rt.impl`). Aliases/imports arrive via other paths and
    // must not be recorded here.
    if (Ty.isResourceType()) {
      CompInst.markDefinedResource(&Ty);
    }
  }
  return {};
}

} // namespace Executor
} // namespace WasmEdge
