#include <algorithm>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iostream>
#include <ranges>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#  ifndef NOMINMAX
#    define NOMINMAX
#    include <windows.h>
#    undef NOMINMAX
#  else
#    include <windows.h>
#  endif
#  undef WIN32_LEAN_AND_MEAN
#else
#  ifndef NOMINMAX
#    define NOMINMAX
#    include <windows.h>
#    undef NOMINMAX
#  else
#    include <windows.h>
#  endif
#endif

using namespace std;

namespace hello
{
  namespace
  {
    template <typename T> T
    adjust_pointer (HMODULE base, size_t offset)
    {
      return reinterpret_cast<T> (reinterpret_cast<uintptr_t> (base) + offset);
    }

    struct
    portable_executable
    {
      HMODULE m;

      PIMAGE_DOS_HEADER d; PIMAGE_NT_HEADERS n; PIMAGE_SECTION_HEADER s;

      explicit
      portable_executable (HMODULE module)
        : m (module),
          d (reinterpret_cast<PIMAGE_DOS_HEADER> (m)),
          n (adjust_pointer<PIMAGE_NT_HEADERS> (m, d->e_lfanew)),
          s (IMAGE_FIRST_SECTION (n))
      {

      }
    };

    void dummy ()
    {
      MessageBoxA(nullptr, "", "", MB_OK);
    }

    using stream = ifstream;
    using stream_iterator = istreambuf_iterator <char>;

    void
    main ()
    {
      ios::sync_with_stdio (false);

      const stream s ("test.exe", ios::binary);
      const vector v (stream_iterator (s.rdbuf ()), {});

      portable_executable src (reinterpret_cast<HMODULE> (const_cast <char*> (&v.at (0)))),
                          dst (GetModuleHandle (nullptr));
      {
        using ranges::for_each;
        using ranges::views::all;
        using ranges::views::filter;
        using ranges::views::iota;
        using ranges::views::take_while;

        for_each (all (span (src.s, src.n->FileHeader.NumberOfSections))
        | filter ([]  (const IMAGE_SECTION_HEADER& s)
        {
          return s.PointerToRawData && s.SizeOfRawData > 0;
        }),

        [&] (const IMAGE_SECTION_HEADER& s)
        {
          const auto v (adjust_pointer<void*> (dst.m, s.VirtualAddress));
          const auto r (adjust_pointer<void*> (src.m, s.PointerToRawData));
          const auto m (min (s.SizeOfRawData, s.Misc.VirtualSize));

          try
          {
            unsigned long old_protect (0);

            if (VirtualProtect (v, m, PAGE_EXECUTE_READWRITE, &old_protect) == 0)
              throw system_error (GetLastError (), system_category ());

            memmove (v, r, m);
          }

          catch (const exception& e)
          {
            cerr << "error: " << e.what ();
          }
        });

        const auto import (&src.n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
        const auto import_descriptor (adjust_pointer<PIMAGE_IMPORT_DESCRIPTOR> (dst.m, import->VirtualAddress));

        for_each (iota (0, INT_MAX)
        | take_while ([import_descriptor] (const auto& x)
        {
          return import_descriptor[x].Name != 0;
        }),

        [&](const auto& x)
        {
          const auto name (adjust_pointer<char*> (dst.m, import_descriptor[x].Name));
          const auto first_thunk (adjust_pointer<PIMAGE_THUNK_DATA> (dst.m, import_descriptor[x].FirstThunk));
          const auto original_first_thunk ([&]
          {
            if (!import_descriptor[x].OriginalFirstThunk)
              return adjust_pointer<PIMAGE_THUNK_DATA> (dst.m, import_descriptor[x].OriginalFirstThunk);
            return first_thunk;
          }());

          for_each (iota (0, INT_MAX)
          | take_while ([&] (const auto& x)
          {
            return original_first_thunk[x].u1.AddressOfData != 0;
          }),

          [&] (const auto& x)
          {
            const auto lib (LoadLibrary (name));
            const auto addr (adjust_pointer<PIMAGE_IMPORT_BY_NAME> (dst.m, original_first_thunk[x].u1.AddressOfData));
            const auto ordinal ([&]
            {
              if (IMAGE_SNAP_BY_ORDINAL (original_first_thunk[x].u1.Ordinal))
                return GetProcAddress (lib, MAKEINTRESOURCEA (IMAGE_ORDINAL(original_first_thunk[x].u1.Ordinal)));
              return GetProcAddress (lib, reinterpret_cast<LPCSTR> (&addr->Name));
            });

            try
            {
              if (!lib)
                throw system_error (GetLastError (), system_category ());

              first_thunk[x].u1.Function = reinterpret_cast<unsigned long> (ordinal ());
            }

            catch (const exception& e)
            {
              cerr << "error: " << e.what ();
            }
          });
        });

        unsigned long old_protect (0);
        VirtualProtect (dst.n, 0x1000, PAGE_EXECUTE_READWRITE, &old_protect);
        dst.n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = src.n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        memmove (dst.n, src.n, sizeof (IMAGE_NT_HEADERS) + dst.n->FileHeader.NumberOfSections * sizeof (IMAGE_SECTION_HEADER));

        reinterpret_cast<FARPROC>(src.n->OptionalHeader.AddressOfEntryPoint + 0x00400000)();
      }
    }
  }
}

int
main (int argc, char* argv[])
{
  hello::main ();
}
