// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2019-2024 Second State INC

#pragma once

#include "ast/component/component.h"
#include "ast/module.h"
#include "ast/type.h"
#include "validator/component_name.h"

#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace WasmEdge {
namespace Validator {

class ComponentContext {
public:
  // ==========================================================================
  // Validation context (one per component scope)
  // ==========================================================================

  struct Context {
    Context(const AST::Component::Component *C,
            const Context *P = nullptr) noexcept
        : Component(C), Parent(P) {}

    // ---- Nested types ----
    // Per-sort slot structs bundling body + externdesc type ascription.
    // Exactly one of {Body, Type} is non-null per slot (Body for inline,
    // Type for imported / outer-aliased).
    struct CoreModuleSlot {
      const AST::Module *Body;
      const AST::Component::CoreDefType *Type;
      CoreModuleSlot() noexcept : Body(nullptr), Type(nullptr) {}
      CoreModuleSlot(const AST::Module &B) noexcept : Body(&B), Type(nullptr) {}
      CoreModuleSlot(const AST::Component::CoreDefType *T) noexcept
          : Body(nullptr), Type(T) {}
    };
    struct ComponentSlot {
      const AST::Component::Component *Body;
      const AST::Component::ComponentType *Type;
      ComponentSlot() noexcept : Body(nullptr), Type(nullptr) {}
      ComponentSlot(const AST::Component::Component &B) noexcept
          : Body(&B), Type(nullptr) {}
      ComponentSlot(const AST::Component::ComponentType *T) noexcept
          : Body(nullptr), Type(T) {}
    };
    // Per-export entry inside an instance's export table.
    // ResourceId is set when ST == Type and the exported type is a resource
    // (so an alias-export onto a new type slot can carry the same identity).
    struct InstanceExport {
      AST::Component::Sort::SortType ST;
      const AST::Component::InstanceType *IT;
      std::optional<uint32_t> NestedInstIdx;
      std::optional<uint64_t> ResourceId;
      // Whether the exported resource is locally defined in the component that
      // produced this instance export, so an alias-export can preserve the
      // locality that gates resource.new/.rep.
      bool ResourceLocallyDefined = false;
      // For ST == Func: the resource id referenced by each param / result (or
      // nullopt where the param / result is not a resource), so an
      // alias-export of the function carries its resource signature for
      // instantiation subtype checks.
      bool HasFuncSig = false;
      std::vector<std::optional<uint64_t>> FuncParamRes;
      std::vector<std::optional<uint64_t>> FuncResultRes;
    };
    // Instance slot. Type is set only when bound via
    // validate(ExternDesc::InstanceType) (GAP-I-5b follow-up otherwise).
    struct InstanceSlot {
      std::unordered_map<std::string, InstanceExport> Exports;
      const AST::Component::InstanceType *Type;
      // True when this instance is import-rooted (an instance import or an
      // alias-export off an import-rooted instance), so a resource surfaced out
      // of it is importable by a function import in this component.
      bool FromImport = false;
      InstanceSlot() : Type(nullptr) {}
      InstanceSlot(const AST::Component::InstanceType *T) : Type(T) {}
    };
    // Per-resource bookkeeping. "Key present in Resources" means resource.
    // The resource's AST body lives on ComponentContext::ResourceRegistry[Id].
    struct ResourceInfo {
      // Canonical identity. Two indices share a resource iff ids match.
      uint64_t Id = 0;
      // True for validate(DefType) in this scope. Gates resource.new/.rep.
      bool LocallyDefined = false;
    };
    // Export of a core:instance. Kind is always set; Mem is populated for
    // memory exports (index-type subtype checks, GAP-CI-1); Func is populated
    // for function exports so an `alias core export` can carry the func type
    // (e.g. resource destructor signature validation).
    struct CoreInstanceExport {
      ExternalType Kind;
      // Stored by value (not pointer): the module-type descriptor getter
      // returns a temporary, so a pointer into it would dangle. Each optional
      // is populated only for its matching Kind, for instantiation subtype
      // checks (GAP-CI-1).
      std::optional<AST::MemoryType> Mem;
      std::optional<AST::TableType> Tab;
      std::optional<AST::GlobalType> Glob;
      // Func type for function exports, so an `alias core export` can carry the
      // func type (e.g. resource destructor signature validation). The SubType
      // is owned by the core type sort space, so a pointer stays valid here.
      const AST::SubType *Func = nullptr;

      CoreInstanceExport() noexcept = default;
      // Copies whichever core extern type is provided (the others stay empty);
      // Func is a stable pointer and stored as-is.
      CoreInstanceExport(ExternalType K, const AST::MemoryType *M,
                         const AST::TableType *T, const AST::GlobalType *G,
                         const AST::SubType *F = nullptr) noexcept
          : Kind(K), Func(F) {
        if (M != nullptr) {
          Mem = *M;
        }
        if (T != nullptr) {
          Tab = *T;
        }
        if (G != nullptr) {
          Glob = *G;
        }
      }
    };

    // ---- Scope identity ----
    const AST::Component::Component *Component;
    const Context *Parent;

    // ---- Core sort index spaces ----
    std::vector<CoreModuleSlot> CoreModules; // core:module
    std::vector<std::unordered_map<std::string, CoreInstanceExport>>
        CoreInstances;                              // core:instance
    std::vector<const AST::SubType *> CoreTypes;    // core:type
    std::vector<const AST::SubType *> CoreFuncs;    // core:func
    std::vector<const AST::TableType *> CoreTables; // core:table
    // Owns its MemoryType copies (not pointers): the source lives in the
    // CoreInstances vector-of-maps, which relocates when later instances are
    // added, so a pointer into it would dangle (GAP-CI-1).
    std::vector<std::optional<AST::MemoryType>> CoreMemories; // core:memory
    std::vector<const AST::GlobalType *> CoreGlobals;         // core:global
    uint32_t CoreTagCount = 0;                                // core:tag

    // ---- Component sort index spaces ----
    std::vector<ComponentSlot> Components;               // component
    std::vector<InstanceSlot> Instances;                 // instance
    std::vector<const AST::Component::DefType *> Types;  // type
    std::vector<const AST::Component::FuncType *> Funcs; // func (i may be null)
    std::vector<bool> ValueConsumed;                     // value (consumed?)

    // ---- Type annotations (keyed by type index) ----
    // ResourceType bodies live on Resources[i].Body (see below).
    std::unordered_map<uint32_t, const AST::Component::InstanceType *>
        InstanceTypes;
    std::unordered_map<uint32_t, const AST::Component::ComponentType *>
        ComponentTypes;
    // CoreDefType (moduletype) bodies, keyed by core:type-idx.
    std::unordered_map<uint32_t, const AST::Component::CoreDefType *>
        CoreModuleTypes;

    // ---- Resource state (keyed by type index) ----
    std::unordered_map<uint32_t, ResourceInfo> Resources;
    // Resource ids exported from this component (directly or via an exported
    // instance), so a function exported from here may reference them.
    std::unordered_set<uint64_t> ExportedResourceIds;
    // Resource ids imported into this component (directly or via an imported
    // instance), so a function imported here may reference them.
    std::unordered_set<uint64_t> ImportableResourceIds;
    // Per component-func-index resource signature (param ids, result ids),
    // recorded when a function is alias-exported from an instance so an
    // instantiation subtype check can compare resource identities.
    std::unordered_map<uint32_t,
                       std::pair<std::vector<std::optional<uint64_t>>,
                                 std::vector<std::optional<uint64_t>>>>
        FuncResourceSigs;

    // ---- Validation state ----
    std::unordered_map<std::string, uint32_t> TypeSubstitutions;
    std::unordered_set<std::string> ImportedNames;
    std::unordered_set<std::string> ExportedNames;
    // Kebab-case resource name → type-idx; consumed by annotated-name
    // validation ([constructor]R / [method]R.f / [static]R.f). Import and
    // export labels live in separate namespaces: Binary.md "annotated names"
    // requires a `[constructor]/[method]/[static]` import to match a preceding
    // resource import and an annotated export to match a resource export,
    // respectively.
    std::unordered_map<std::string, uint32_t> ImportResourceLabels;
    std::unordered_map<std::string, uint32_t> ExportResourceLabels;

    // ---- Size queries (used by outer-alias validation on parent ctxs) ----
    uint32_t getSortIndexSize(AST::Component::Sort::SortType ST) const noexcept;
    uint32_t
    getCoreSortIndexSize(AST::Component::Sort::CoreSortType ST) const noexcept;

    bool AddImportedName(const ComponentName &Name) noexcept;
    bool AddExportedName(const ComponentName &Name) noexcept;
  };

  // Per-id row of the session-global resource registry. Held by
  // ComponentContext::ResourceRegistry; vector index IS the resource id.
  struct ResourceRegistryEntry {
    const AST::Component::ResourceType *Body = nullptr;
  };

  // ==========================================================================
  // Context stack management
  // ==========================================================================

  void reset() noexcept {
    CompCtxs.clear();
    ResourceRegistry.clear();
  }

  /// Push a new validation scope for a real component.
  void enterComponent(const AST::Component::Component *C) noexcept {
    const Context *Parent = CompCtxs.empty() ? nullptr : &CompCtxs.back();
    CompCtxs.emplace_back(C, Parent);
  }

  /// Push a new validation scope for a type definition
  /// (componenttype, instancetype, or moduletype).
  void enterTypeDefinition() noexcept {
    const Context *Parent = CompCtxs.empty() ? nullptr : &CompCtxs.back();
    CompCtxs.emplace_back(nullptr, Parent);
  }

  void exitComponent() noexcept {
    assuming(!CompCtxs.empty());
    CompCtxs.pop_back();
  }

  /// Returns true if the current scope is a type definition scope
  /// (componenttype or instancetype), not a real component scope.
  bool isTypeDefinitionScope() const noexcept {
    return !CompCtxs.empty() && CompCtxs.back().Component == nullptr;
  }

  Context &getCurrentContext() noexcept {
    assuming(!CompCtxs.empty());
    return CompCtxs.back();
  }
  const Context &getCurrentContext() const noexcept {
    assuming(!CompCtxs.empty());
    return CompCtxs.back();
  }

  // ==========================================================================
  // Index space size queries (generic dispatch by sort enum)
  // ==========================================================================

  uint32_t getSortIndexSize(AST::Component::Sort::SortType ST) const noexcept {
    return getCurrentContext().getSortIndexSize(ST);
  }
  uint32_t
  getCoreSortIndexSize(AST::Component::Sort::CoreSortType ST) const noexcept {
    return getCurrentContext().getCoreSortIndexSize(ST);
  }

  // ==========================================================================
  // Generic index space increment (for dynamic sort values)
  // ==========================================================================

  uint32_t incSortIndexSize(AST::Component::Sort::SortType ST) noexcept;
  uint32_t incCoreSortIndexSize(AST::Component::Sort::CoreSortType ST) noexcept;

  // ==========================================================================
  // core:module
  // ==========================================================================

  /// Append a core-module slot. Slot's implicit constructors accept
  /// `const AST::Module &` (inline body), `const CoreDefType *` (typed
  /// import / alias), or nothing (empty slot, used by outer-alias
  /// validation and incCoreSortIndexSize).
  uint32_t addCoreModule(Context::CoreModuleSlot S = {}) noexcept {
    auto &Ctx = getCurrentContext();
    uint32_t Idx = static_cast<uint32_t>(Ctx.CoreModules.size());
    Ctx.CoreModules.push_back(std::move(S));
    return Idx;
  }

  /// Read a core-module slot. Callers access `.Body` (inline body) or
  /// `.Type` (externdesc-bound moduletype) as needed.
  const Context::CoreModuleSlot &getCoreModule(uint32_t Idx) const noexcept {
    return getCurrentContext().CoreModules.at(Idx);
  }

  /// Returns the CoreDefType (a moduletype) stored at a core:type index, or
  /// nullptr if the core type is not a ModuleType (or its body is not
  /// visible here).
  const AST::Component::CoreDefType *
  getCoreModuleType(uint32_t TypeIdx) const noexcept {
    const auto &Ctx = getCurrentContext();
    auto It = Ctx.CoreModuleTypes.find(TypeIdx);
    return It != Ctx.CoreModuleTypes.end() ? It->second : nullptr;
  }

  /// Bind a CoreDefType (a moduletype) to a core:type index. Called by
  /// validate(CoreDefType) when adding a moduletype to the core:type space.
  void setCoreModuleType(uint32_t TypeIdx,
                         const AST::Component::CoreDefType *CT) noexcept {
    getCurrentContext().CoreModuleTypes[TypeIdx] = CT;
  }

  // ==========================================================================
  // core:instance
  // ==========================================================================

  uint32_t addCoreInstance() noexcept {
    auto &V = getCurrentContext().CoreInstances;
    uint32_t Idx = static_cast<uint32_t>(V.size());
    V.emplace_back();
    return Idx;
  }

  const std::unordered_map<std::string, Context::CoreInstanceExport> &
  getCoreInstance(uint32_t Idx) const noexcept {
    return getCurrentContext().CoreInstances.at(Idx);
  }

  void setInstanceExportFuncSig(uint32_t InstIdx, std::string_view Name,
                                std::vector<std::optional<uint64_t>> Params,
                                std::vector<std::optional<uint64_t>> Results) {
    auto &Exports = getCurrentContext().Instances.at(InstIdx).Exports;
    auto It = Exports.find(std::string(Name));
    if (It != Exports.end()) {
      It->second.HasFuncSig = true;
      It->second.FuncParamRes = std::move(Params);
      It->second.FuncResultRes = std::move(Results);
    }
  }

  void addCoreInstanceExport(uint32_t InstIdx, std::string_view Name,
                             ExternalType ET,
                             const AST::MemoryType *Mem = nullptr,
                             const AST::TableType *Tab = nullptr,
                             const AST::GlobalType *Glob = nullptr,
                             const AST::SubType *Func = nullptr) {
    getCurrentContext().CoreInstances.at(InstIdx)[std::string(Name)] =
        Context::CoreInstanceExport{ET, Mem, Tab, Glob, Func};
  }

  // ==========================================================================
  // core:type / core:func / core:table / core:memory / core:global / core:tag
  // ==========================================================================

  uint32_t addCoreType(const AST::SubType *ST = nullptr) noexcept {
    auto &V = getCurrentContext().CoreTypes;
    uint32_t Idx = static_cast<uint32_t>(V.size());
    V.push_back(ST);
    return Idx;
  }
  uint32_t addCoreFunc(const AST::SubType *ST = nullptr) noexcept {
    auto &V = getCurrentContext().CoreFuncs;
    uint32_t Idx = static_cast<uint32_t>(V.size());
    V.push_back(ST);
    return Idx;
  }
  /// Add a core function whose signature is synthesized during validation
  /// (e.g., the type produced by `canon lower`). The SubType is owned by the
  /// ComponentContext so its address stays stable for later lookups.
  uint32_t addCoreFuncOwned(std::unique_ptr<AST::SubType> ST) noexcept {
    SynthesizedCoreFuncTypes.push_back(std::move(ST));
    return addCoreFunc(SynthesizedCoreFuncTypes.back().get());
  }
  const AST::SubType *getCoreFunc(uint32_t Idx) const noexcept {
    const auto &V = getCurrentContext().CoreFuncs;
    return Idx < V.size() ? V[Idx] : nullptr;
  }
  /// Look up a registered `core:type` entry. Used by canon lift to retrieve
  /// the imported `$callee`'s declared core type when threaded from
  /// CoreImportDesc.
  const AST::SubType *getCoreType(uint32_t Idx) const noexcept {
    const auto &V = getCurrentContext().CoreTypes;
    return Idx < V.size() ? V[Idx] : nullptr;
  }

  uint32_t addCoreTable(const AST::TableType *TT = nullptr) noexcept {
    auto &V = getCurrentContext().CoreTables;
    uint32_t Idx = static_cast<uint32_t>(V.size());
    V.push_back(TT);
    return Idx;
  }
  uint32_t
  addCoreMemory(std::optional<AST::MemoryType> MT = std::nullopt) noexcept {
    auto &V = getCurrentContext().CoreMemories;
    uint32_t Idx = static_cast<uint32_t>(V.size());
    V.push_back(std::move(MT));
    return Idx;
  }
  const AST::MemoryType *getCoreMemory(uint32_t Idx) const noexcept {
    const auto &V = getCurrentContext().CoreMemories;
    return Idx < V.size() && V[Idx].has_value() ? &*V[Idx] : nullptr;
  }
  uint32_t addCoreGlobal(const AST::GlobalType *GT = nullptr) noexcept {
    auto &V = getCurrentContext().CoreGlobals;
    uint32_t Idx = static_cast<uint32_t>(V.size());
    V.push_back(GT);
    return Idx;
  }
  uint32_t addCoreTag() noexcept { return getCurrentContext().CoreTagCount++; }

  // ==========================================================================
  // component
  // ==========================================================================

  /// Append a component slot. Slot's implicit constructors accept
  /// `const Component &` (inline body), `const ComponentType *` (typed
  /// import / alias), or nothing (empty slot).
  uint32_t addComponent(Context::ComponentSlot S = {}) noexcept {
    auto &Ctx = getCurrentContext();
    uint32_t Idx = static_cast<uint32_t>(Ctx.Components.size());
    Ctx.Components.push_back(std::move(S));
    return Idx;
  }

  /// Read a component slot. Callers access `.Body` (inline body) or
  /// `.Type` (externdesc-bound ComponentType) as needed.
  const Context::ComponentSlot &getComponent(uint32_t Idx) const noexcept {
    return getCurrentContext().Components.at(Idx);
  }

  /// Returns the ComponentType stored at a type index, or nullptr if the
  /// type is not a ComponentType (or its body is not visible here).
  const AST::Component::ComponentType *
  getComponentType(uint32_t TypeIdx) const noexcept {
    const auto &Ctx = getCurrentContext();
    auto It = Ctx.ComponentTypes.find(TypeIdx);
    return It != Ctx.ComponentTypes.end() ? It->second : nullptr;
  }

  // The scope an outer alias targets: Ct parent hops up. nullptr if Ct
  // exceeds the enclosing depth.
  const Context *resolveOuterContext(uint32_t Ct) const noexcept {
    uint32_t Hops = 0;
    const Context *T = &getCurrentContext();
    while (Ct > Hops && T != nullptr) {
      T = T->Parent;
      ++Hops;
    }
    return T;
  }

  // Reproduce an outer-aliased core module's slot into the alias's slot
  // DstIdx, so its exports stay enumerable when the alias is instantiated.
  void carryOuterCoreModule(uint32_t DstIdx, uint32_t Ct,
                            uint32_t SrcIdx) noexcept {
    const Context *O = resolveOuterContext(Ct);
    auto &Dst = getCurrentContext().CoreModules;
    if (O != nullptr && SrcIdx < O->CoreModules.size() && DstIdx < Dst.size()) {
      Dst[DstIdx] = O->CoreModules[SrcIdx];
    }
  }

  // Component analogue of carryOuterCoreModule.
  void carryOuterComponent(uint32_t DstIdx, uint32_t Ct,
                           uint32_t SrcIdx) noexcept {
    const Context *O = resolveOuterContext(Ct);
    auto &Dst = getCurrentContext().Components;
    if (O != nullptr && SrcIdx < O->Components.size() && DstIdx < Dst.size()) {
      Dst[DstIdx] = O->Components[SrcIdx];
    }
  }

  // Inherit an outer-aliased resource type's identity into the alias's type
  // slot DstIdx, so own/borrow checks and TypeBound (eq i) propagation in this
  // scope still recognise the aliased type as a resource. The alias does not
  // locally define the resource, so LocallyDefined stays false (it must not
  // gate resource.new/.rep here).
  void carryOuterResource(uint32_t DstIdx, uint32_t Ct,
                          uint32_t SrcIdx) noexcept {
    const Context *O = resolveOuterContext(Ct);
    if (O == nullptr) {
      return;
    }
    auto It = O->Resources.find(SrcIdx);
    if (It != O->Resources.end()) {
      getCurrentContext().Resources[DstIdx] = {It->second.Id,
                                               /*LocallyDefined=*/false};
    }
  }

  // Whether the type at SrcIdx in the scope Ct hops up transitively references
  // a resource defined in that scope (own/borrow directly or nested in
  // record/tuple/list/option/result/variant). Used to reject an outer alias
  // that would let a resource escape an enclosing concrete component.
  bool outerTypeRefsResource(uint32_t Ct, uint32_t SrcIdx) const noexcept {
    const Context *O = resolveOuterContext(Ct);
    if (O == nullptr) {
      return false;
    }
    return defTypeRefsResourceIn(O, SrcIdx, 0);
  }

  // ==========================================================================
  // instance
  // ==========================================================================

  /// Append an instance slot. Slot's implicit constructor accepts
  /// `const InstanceType *` (typed source) or nothing (untyped — used by
  /// inline-export / (instantiate ...) sources).
  uint32_t addInstance(Context::InstanceSlot S = {}) {
    auto &Ctx = getCurrentContext();
    uint32_t Idx = static_cast<uint32_t>(Ctx.Instances.size());
    Ctx.Instances.push_back(std::move(S));
    return Idx;
  }

  using InstanceExport = Context::InstanceExport;

  /// Read an instance slot. Callers access `.Exports` (export table) or
  /// `.Type` (externdesc-bound InstanceType) as needed.
  const Context::InstanceSlot &getInstance(uint32_t Idx) const noexcept {
    return getCurrentContext().Instances.at(Idx);
  }

  /// Mark / query whether an instance slot is import-rooted (see InstanceSlot).
  void setInstanceFromImport(uint32_t Idx) noexcept {
    getCurrentContext().Instances.at(Idx).FromImport = true;
  }
  bool isInstanceFromImport(uint32_t Idx) const noexcept {
    return getCurrentContext().Instances.at(Idx).FromImport;
  }

  void addInstanceExport(uint32_t InstIdx, std::string_view Name,
                         AST::Component::Sort::SortType ST,
                         const AST::Component::InstanceType *IT = nullptr,
                         std::optional<uint32_t> NestedInstIdx = std::nullopt,
                         std::optional<uint64_t> ResourceId = std::nullopt,
                         bool ResourceLocallyDefined = false) noexcept {
    getCurrentContext().Instances.at(InstIdx).Exports[std::string(Name)] = {
        ST,
        IT,
        NestedInstIdx,
        ResourceId,
        ResourceLocallyDefined,
        /*HasFuncSig=*/false,
        {},
        {}};
  }

  // ==========================================================================
  // type
  // ==========================================================================

  /// Append a type slot. IsLocal=false for resource type imports and
  /// outer-alias resources, true otherwise.
  uint32_t addType(const AST::Component::DefType *DT = nullptr,
                   bool IsLocal = true) noexcept {
    return addTypeImpl(DT, IsLocal);
  }

  const AST::Component::DefType *getDefType(uint32_t Idx) const noexcept {
    const auto &Ctx = getCurrentContext();
    if (Idx < Ctx.Types.size()) {
      return Ctx.Types[Idx];
    }
    return nullptr;
  }

  const AST::Component::InstanceType *
  getInstanceType(uint32_t Idx) const noexcept {
    const auto &Ctx = getCurrentContext();
    auto It = Ctx.InstanceTypes.find(Idx);
    return It != Ctx.InstanceTypes.end() ? It->second : nullptr;
  }

  // ==========================================================================
  // resource
  // ==========================================================================

  /// Allocate a fresh resource id, pushing a new registry row. Body is
  /// nullptr for (sub resource) imports.
  uint64_t allocateFreshResourceId(
      const AST::Component::ResourceType *Body = nullptr) noexcept {
    uint64_t Id = ResourceRegistry.size();
    ResourceRegistry.push_back({Body});
    return Id;
  }

  /// Bind a ResourceInfo to a type index in the current scope.
  void addResource(uint32_t TypeIdx, Context::ResourceInfo Info) noexcept {
    getCurrentContext().Resources[TypeIdx] = Info;
  }

  /// ResourceInfo at this type index, or nullptr if not a resource.
  const Context::ResourceInfo *getResource(uint32_t Idx) const noexcept {
    const auto &R = getCurrentContext().Resources;
    auto It = R.find(Idx);
    return It != R.end() ? &It->second : nullptr;
  }

  /// Mark / query a resource (by canonical id) as exported from this
  /// component, so an exported function may reference it.
  void markResourceExported(uint64_t Id) noexcept {
    getCurrentContext().ExportedResourceIds.insert(Id);
  }
  bool isResourceExported(uint64_t Id) const noexcept {
    const auto &S = getCurrentContext().ExportedResourceIds;
    return S.find(Id) != S.end();
  }
  void markResourceImportable(uint64_t Id) noexcept {
    getCurrentContext().ImportableResourceIds.insert(Id);
  }
  bool isResourceImportable(uint64_t Id) const noexcept {
    const auto &S = getCurrentContext().ImportableResourceIds;
    return S.find(Id) != S.end();
  }
  void setFuncResourceSig(uint32_t FuncIdx,
                          std::vector<std::optional<uint64_t>> Params,
                          std::vector<std::optional<uint64_t>> Results) {
    getCurrentContext().FuncResourceSigs[FuncIdx] = {std::move(Params),
                                                     std::move(Results)};
  }
  const std::pair<std::vector<std::optional<uint64_t>>,
                  std::vector<std::optional<uint64_t>>> *
  getFuncResourceSig(uint32_t FuncIdx) const noexcept {
    const auto &M = getCurrentContext().FuncResourceSigs;
    auto It = M.find(FuncIdx);
    return It == M.end() ? nullptr : &It->second;
  }

  /// Register a kebab-case resource name (from a TypeBound import / export) so
  /// annotated names ([constructor]R / [method]R.f / [static]R.f) resolve. The
  /// import and export namespaces are kept separate so an annotated name only
  /// matches a preceding resource declared in the same direction (Binary.md
  /// "annotated names", the "respectively" rule).
  void addResourceLabel(std::string_view Name, uint32_t TypeIdx,
                        bool IsExport) noexcept {
    auto &M = IsExport ? getCurrentContext().ExportResourceLabels
                       : getCurrentContext().ImportResourceLabels;
    M.emplace(std::string(Name), TypeIdx);
  }

  bool hasResourceLabel(std::string_view Name, bool IsExport) const noexcept {
    const auto &M = IsExport ? getCurrentContext().ExportResourceLabels
                             : getCurrentContext().ImportResourceLabels;
    return M.find(std::string(Name)) != M.end();
  }

  // Resolve a kebab resource label to its type index, if present.
  std::optional<uint32_t> getResourceLabel(std::string_view Name,
                                           bool IsExport) const noexcept {
    const auto &M = IsExport ? getCurrentContext().ExportResourceLabels
                             : getCurrentContext().ImportResourceLabels;
    auto It = M.find(std::string(Name));
    if (It == M.end()) {
      return std::nullopt;
    }
    return It->second;
  }

  // ==========================================================================
  // func / value
  // ==========================================================================

  uint32_t addFunc(const AST::Component::FuncType *FT = nullptr) noexcept {
    auto &V = getCurrentContext().Funcs;
    uint32_t Idx = static_cast<uint32_t>(V.size());
    V.push_back(FT);
    return Idx;
  }
  const AST::Component::FuncType *getFunc(uint32_t Idx) const noexcept {
    const auto &V = getCurrentContext().Funcs;
    return Idx < V.size() ? V[Idx] : nullptr;
  }
  uint32_t addValue(bool Consumed = false) noexcept {
    auto &V = getCurrentContext().ValueConsumed;
    uint32_t Idx = static_cast<uint32_t>(V.size());
    V.push_back(Consumed);
    return Idx;
  }

  Expect<void> consumeValue(uint32_t Idx) noexcept {
    auto &V = getCurrentContext().ValueConsumed;
    if (Idx >= V.size()) {
      return Unexpect(ErrCode::Value::InvalidIndex);
    }
    if (V[Idx]) {
      return Unexpect(ErrCode::Value::ComponentValueAlreadyConsumed);
    }
    V[Idx] = true;
    return {};
  }

  std::optional<uint32_t> firstUnconsumedValue() const noexcept {
    const auto &V = getCurrentContext().ValueConsumed;
    for (uint32_t I = 0; I < V.size(); ++I) {
      if (!V[I]) {
        return I;
      }
    }
    return std::nullopt;
  }

  // ==========================================================================
  // Validation state
  // ==========================================================================

  void substituteTypeImport(const std::string &ImportName,
                            uint32_t TypeIdx) noexcept {
    getCurrentContext().TypeSubstitutions[ImportName] = TypeIdx;
  }

  std::optional<uint32_t>
  getSubstitutedType(const std::string &ImportName) const {
    const auto &Ctx = getCurrentContext();
    auto It = Ctx.TypeSubstitutions.find(ImportName);
    if (It != Ctx.TypeSubstitutions.end()) {
      return It->second;
    }
    return std::nullopt;
  }

  bool addImportedName(const ComponentName &Name) noexcept {
    return getCurrentContext().AddImportedName(Name);
  }

  /// Returns false if the export name violates strong-uniqueness.
  bool addExportedName(const ComponentName &Name) noexcept {
    return getCurrentContext().AddExportedName(Name);
  }

private:
  // Recursive helpers for outerTypeRefsResource (depth-guarded).
  bool valTypeRefsResource(const Context *O, const ComponentValType &VT,
                           unsigned Depth) const noexcept {
    if (VT.getCode() == ComponentTypeCode::Own ||
        VT.getCode() == ComponentTypeCode::Borrow) {
      return O->Resources.find(VT.getTypeIndex()) != O->Resources.end();
    }
    if (VT.getCode() == ComponentTypeCode::TypeIndex) {
      return defTypeRefsResourceIn(O, VT.getTypeIndex(), Depth + 1);
    }
    return false;
  }
  bool defValRefsResource(const Context *O, const AST::Component::DefValType &D,
                          unsigned Depth) const noexcept {
    if (D.isOwnTy()) {
      return O->Resources.find(D.getOwn().Idx) != O->Resources.end();
    }
    if (D.isBorrowTy()) {
      return O->Resources.find(D.getBorrow().Idx) != O->Resources.end();
    }
    if (D.isRecordTy()) {
      for (const auto &F : D.getRecord().LabelTypes) {
        if (valTypeRefsResource(O, F.getValType(), Depth)) {
          return true;
        }
      }
    } else if (D.isTupleTy()) {
      for (const auto &T : D.getTuple().Types) {
        if (valTypeRefsResource(O, T, Depth)) {
          return true;
        }
      }
    } else if (D.isListTy()) {
      return valTypeRefsResource(O, D.getList().ValTy, Depth);
    } else if (D.isOptionTy()) {
      return valTypeRefsResource(O, D.getOption().ValTy, Depth);
    } else if (D.isResultTy()) {
      const auto &R = D.getResult();
      if (R.ValTy.has_value() && valTypeRefsResource(O, *R.ValTy, Depth)) {
        return true;
      }
      if (R.ErrTy.has_value() && valTypeRefsResource(O, *R.ErrTy, Depth)) {
        return true;
      }
    } else if (D.isVariantTy()) {
      for (const auto &C : D.getVariant().Cases) {
        if (C.second.has_value() && valTypeRefsResource(O, *C.second, Depth)) {
          return true;
        }
      }
    } else if (D.isStreamTy()) {
      return D.getStream().ValTy.has_value() &&
             valTypeRefsResource(O, *D.getStream().ValTy, Depth);
    } else if (D.isFutureTy()) {
      return D.getFuture().ValTy.has_value() &&
             valTypeRefsResource(O, *D.getFuture().ValTy, Depth);
    }
    return false;
  }
  // True if an `alias outer` declaration inside a type body (whose defining
  // scope is O) targets a resource in the scope it reaches. From inside the
  // body, Ct == 1 reaches O, Ct == 2 reaches O's parent, and so on.
  bool aliasOuterHitsResource(const Context *O,
                              const AST::Component::Alias &A) const noexcept {
    if (A.getTargetType() != AST::Component::Alias::TargetType::Outer) {
      return false;
    }
    if (A.getSort().isCore() ||
        A.getSort().getSortType() != AST::Component::Sort::SortType::Type) {
      return false;
    }
    const uint32_t Ct = A.getOuter().first;
    const uint32_t Idx = A.getOuter().second;
    if (Ct < 1u) {
      return false; // self-reference within the type body
    }
    const Context *R = O;
    for (uint32_t H = 1u; H < Ct && R != nullptr; ++H) {
      R = R->Parent;
    }
    return R != nullptr && R->Resources.find(Idx) != R->Resources.end();
  }
  bool defTypeRefsResourceIn(const Context *O, uint32_t Idx,
                             unsigned Depth) const noexcept {
    if (Depth > 16u || Idx >= O->Types.size()) {
      return false;
    }
    if (O->Resources.find(Idx) != O->Resources.end()) {
      return true; // the type at Idx is itself a resource
    }
    const auto *DT = O->Types[Idx];
    if (DT == nullptr) {
      return false;
    }
    if (DT->isDefValType()) {
      return defValRefsResource(O, DT->getDefValType(), Depth);
    }
    // Component / instance types reference a resource if a declaration outer-
    // aliases one from an enclosing scope (Explainer free-variable rule).
    if (DT->isComponentType()) {
      for (const auto &CD : DT->getComponentType().getDecl()) {
        if (CD.isInstanceDecl() && CD.getInstance().isAlias() &&
            aliasOuterHitsResource(O, CD.getInstance().getAlias())) {
          return true;
        }
      }
    } else if (DT->isInstanceType()) {
      for (const auto &ID : DT->getInstanceType().getDecl()) {
        if (ID.isAlias() && aliasOuterHitsResource(O, ID.getAlias())) {
          return true;
        }
      }
    }
    return false;
  }

  uint32_t addTypeImpl(const AST::Component::DefType *DT,
                       bool IsLocal) noexcept {
    auto &Ctx = getCurrentContext();
    uint32_t Idx = static_cast<uint32_t>(Ctx.Types.size());
    Ctx.Types.push_back(DT);
    if (DT != nullptr) {
      if (DT->isInstanceType()) {
        Ctx.InstanceTypes[Idx] = &DT->getInstanceType();
      } else if (DT->isResourceType()) {
        // Locally-defined: body goes to the registry; IsLocal sets locality.
        Ctx.Resources[Idx] = {allocateFreshResourceId(&DT->getResourceType()),
                              IsLocal};
      } else if (DT->isComponentType()) {
        Ctx.ComponentTypes[Idx] = &DT->getComponentType();
      }
    }
    return Idx;
  }

  std::deque<Context> CompCtxs;

  // Session-global resource registry; vector index IS the resource id.
  std::vector<ResourceRegistryEntry> ResourceRegistry;

  /// Storage for SubTypes synthesized during validation (e.g., by
  /// `canon lower`). Owned here so the pointers handed back by getCoreFunc
  /// remain valid for the lifetime of the ComponentContext.
  std::vector<std::unique_ptr<AST::SubType>> SynthesizedCoreFuncTypes;
};

} // namespace Validator
} // namespace WasmEdge
