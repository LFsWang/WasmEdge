// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2019-2024 Second State INC

//===-- wasmedge/runtime/instance/component/resource_table.h --------------===//
//
// Part of the WasmEdge Project.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file contains the per-component-instance resource handle table used by
/// the canonical ABI resource built-ins and own/borrow lift/lower. It mirrors
/// the spec's `Table` / `ResourceHandle` (CanonicalABI.md, definitions.py
/// `class Table`, `class ResourceHandle`).
///
//===----------------------------------------------------------------------===//
#pragma once

#include "common/errcode.h"

#include <cstdint>
#include <memory>
#include <vector>

namespace WasmEdge {

namespace AST {
namespace Component {
class DefType;
} // namespace Component
} // namespace AST

namespace Runtime {
namespace Instance {

class ComponentInstance; // forward decl for the resource's defining instance

namespace Component {

struct ResourceHandle; // forward decl for BorrowScope

/// The synchronous-ABI borrow scope. The spec tracks borrows per Task/Subtask
/// (CanonicalABI.md `Task.num_borrows`, `Subtask.lenders`); in the sync ABI the
/// scope is a single lift/lower call frame. `NumBorrows` counts borrow handles
/// lowered into the callee that must be dropped before the call returns;
/// `Lenders` records source handles whose `NumLends` were bumped by lift_borrow
/// so they can be decremented when the call resolves.
struct BorrowScope {
  uint32_t NumBorrows = 0;
  std::vector<ResourceHandle *> Lenders;

  void addLender(ResourceHandle *H) noexcept;
  void resolve() noexcept;
};

/// A single live resource handle. Mirrors definitions.py `class
/// ResourceHandle`. `Rt` is the resource type identity: the `DefType *` of the
/// resource decl in the defining instance's type space (pointer identity
/// matches the spec's per-instance `ResourceType` object identity and the
/// validator's shared `ResourceId` across aliases). `Rep` is the opaque
/// representation (i32 only in the current scope).
struct ResourceHandle {
  const AST::Component::DefType *Rt = nullptr;
  const ComponentInstance *DefiningInst = nullptr;
  uint32_t Rep = 0;
  bool Own = false;
  BorrowScope *Scope = nullptr; // borrow scope when !Own, else nullptr
  uint32_t NumLends = 0;
};

inline void BorrowScope::addLender(ResourceHandle *H) noexcept {
  H->NumLends++;
  Lenders.push_back(H);
}
inline void BorrowScope::resolve() noexcept {
  for (auto *H : Lenders) {
    if (H->NumLends > 0) {
      H->NumLends--;
    }
  }
  Lenders.clear();
}

/// Per-component-instance handle table. Mirrors definitions.py `class Table`:
/// a dense array with a free-list, index 0 reserved as the null sentinel, and a
/// 2**28-1 length cap. Elements are heap-allocated so `get()` pointers stay
/// stable across `add()` (a BorrowScope keeps raw `ResourceHandle *` lenders).
class ResourceTable {
public:
  ResourceTable() noexcept { Array.emplace_back(nullptr); }

  /// Table.get: trap if out of range or the slot is empty.
  Expect<ResourceHandle *> get(uint32_t I) noexcept {
    using namespace std::literals;
    if (I >= Array.size() || !Array[I]) {
      spdlog::error(ErrCode::Value::ComponentTrap);
      spdlog::error("    canonical ABI: invalid resource handle {}"sv, I);
      return Unexpect(ErrCode::Value::ComponentTrap);
    }
    return Array[I].get();
  }

  /// Table.add: reuse a free slot if any, else append; trap on overflow.
  Expect<uint32_t> add(ResourceHandle H) noexcept {
    using namespace std::literals;
    if (!Free.empty()) {
      uint32_t I = Free.back();
      Free.pop_back();
      Array[I] = std::make_unique<ResourceHandle>(H);
      return I;
    }
    const uint64_t I = Array.size();
    if (I > MaxLength) {
      spdlog::error(ErrCode::Value::ComponentTrap);
      spdlog::error("    canonical ABI: resource table overflow"sv);
      return Unexpect(ErrCode::Value::ComponentTrap);
    }
    Array.push_back(std::make_unique<ResourceHandle>(H));
    return static_cast<uint32_t>(I);
  }

  /// Table.remove: get, clear the slot, push the index onto the free-list.
  Expect<ResourceHandle> remove(uint32_t I) noexcept {
    EXPECTED_TRY(auto *H, get(I));
    ResourceHandle Out = *H;
    Array[I].reset();
    Free.push_back(I);
    return Out;
  }

private:
  static constexpr uint64_t MaxLength = (UINT64_C(1) << 28) - 1;
  std::vector<std::unique_ptr<ResourceHandle>> Array;
  std::vector<uint32_t> Free;
};

} // namespace Component
} // namespace Instance
} // namespace Runtime
} // namespace WasmEdge
