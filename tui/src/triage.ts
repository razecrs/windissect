export interface TriageSymbol {
  id: string;
  demangled?: string;
  library?: boolean;
  kind?: string;
}

export function helperReason(symbol: TriageSymbol): string | undefined {
  if (symbol.library) return 'Windissect library/runtime classification';
  if (symbol.kind === 'thunk') return 'trivial thunk or forwarding stub';
  const name = symbol.demangled ?? symbol.id;
  const rules: Array<[RegExp, string]> = [
    [/^__imp_load_/iu, 'delay-import loader helper'],
    [/^(?:__|_guard_|_security_|_except_handler|_C_specific_handler)/iu, 'compiler/exception runtime name'],
    [/(?:std::|__std_|basic_string|vector<|allocator<)/iu, 'C++ standard-library implementation'],
    [/(?:wil::details|wistd::|Microsoft::WRL::Details)/iu, 'framework implementation detail'],
    [/(?:dynamic initializer|dynamic atexit destructor|lambda_invoker)/iu, 'compiler-generated initialization or lambda glue'],
    [/(?:memcpy|memset|memcmp|purecall|onexit|type_info)/iu, 'CRT helper signature'],
  ];
  return rules.find(([pattern]) => pattern.test(name))?.[1];
}
