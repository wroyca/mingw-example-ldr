OUTPUT_FORMAT(pei-i386)

SEARCH_DIR("/mingw/lib");
SEARCH_DIR("/mingw/mingw32/lib");
SEARCH_DIR("/lib");
SEARCH_DIR("/usr/lib");
SEARCH_DIR("/usr/local/lib");

SECTIONS
{
  . = SIZEOF_HEADERS;
  . = ALIGN(__section_alignment__);

  .__mana __image_base__ + (__section_alignment__ < 0x1000 ? . : __section_alignment__):
  {
    . = 0xc3b6c40; *(.__mana); /* Aligning to nearest 0x1000 boundary for 0x00401000*/
  }

  /*
   * https://github.com/msys2/msys2-runtime/tree/cygwin/master/winsup/cygwin/cygwin.sc.in
   */

  .text BLOCK(__section_alignment__):
  {
    *(.init)
    *(.text)
    *(SORT(.text$*))
    *(.text.*)
    *(.glue_7t)
    *(.glue_7)
    ___CTOR_LIST__ = .; __CTOR_LIST__ = .; LONG (-1); *(SORT(.ctors.*)); *(.ctors); *(.ctor); LONG (0);
    ___DTOR_LIST__ = .; __DTOR_LIST__ = .; LONG (-1); *(SORT(.dtors.*)); *(.dtors); *(.dtor); LONG (0);
    *(.fini)
    *(.gcc_exc)
    etext = .;
    *(.gcc_except_table)
  }

  .autoload_text BLOCK(__section_alignment__):
  {
    *(.*_autoload_text);
  }

  .data BLOCK(__section_alignment__):
  {
    __data_start__ = .;
    *(.data)
    *(.data2)
    *(SORT(.data$*))
    __data_end__ = .;
    *(.data_cygwin_nocopy)
  }

  .rdata BLOCK(__section_alignment__):
  {
    *(.rdata)
    *(SORT(.rdata$*))
    *(.rdata_cygwin_nocopy)
    ___RUNTIME_PSEUDO_RELOC_LIST__ = .;
    __RUNTIME_PSEUDO_RELOC_LIST__ = .;
    *(.rdata_runtime_pseudo_reloc)
    ___RUNTIME_PSEUDO_RELOC_LIST_END__ = .;
    __RUNTIME_PSEUDO_RELOC_LIST_END__ = .;
  }

  .eh_frame BLOCK(__section_alignment__):
  {
    *(.eh_frame*)
  }

  .pdata BLOCK(__section_alignment__):
  {
    *(.pdata*)
  }

  .bss BLOCK(__section_alignment__) :
  {
    __bss_start__ = .;
    *(.bss)
    *(COMMON)
    __bss_end__ = .;
  }

  .edata BLOCK(__section_alignment__) :
  {
    *(.edata)
  }

  .reloc BLOCK(__section_alignment__) :
  {
    *(.reloc)
  }

  .cygwin_dll_common BLOCK(__section_alignment__):
  {
    *(.cygwin_dll_common)
  }

  .idata BLOCK(__section_alignment__) :
  {
    SORT(*)(.idata$2)
    SORT(*)(.idata$3)

    /* Marks the end of the import list. */
    LONG (0); LONG (0); LONG (0); LONG (0); LONG (0);

    SORT(*)(.idata$4)
    SORT(*)(.idata$5)
    SORT(*)(.idata$6)
    SORT(*)(.idata$7)

    . = ALIGN(16);
  }

  .rsrc BLOCK(__section_alignment__):
  {
    *(.rsrc)
    *(SORT(.rsrc$*))
  }

  /DISCARD/ :
  {
    *(.debug$S)
    *(.debug$T)
    *(.debug$F)
    *(.drectve)
  }

  .stab BLOCK(__section_alignment__) (NOLOAD):
  {
    *(.stab)
  }

  .stabstr BLOCK(__section_alignment__) (NOLOAD):
  {
    *(.stabstr)
  }

  /* DWARF 1.1 and DWARF 2 */
  .debug_aranges   BLOCK(__section_alignment__) (NOLOAD) : { *(.debug_aranges) }
  .debug_pubnames  BLOCK(__section_alignment__) (NOLOAD) : { *(.debug_pubnames) }
  .debug_pubtypes  BLOCK(__section_alignment__) (NOLOAD) : { *(.debug_pubtypes) }

  /* DWARF 2 */
  .debug_info      BLOCK(__section_alignment__) (NOLOAD) : { *(.debug_info) }
  .debug_abbrev    BLOCK(__section_alignment__) (NOLOAD) : { *(.debug_abbrev) }
  .debug_line      BLOCK(__section_alignment__) (NOLOAD) : { *(.debug_line) }
  .debug_frame     BLOCK(__section_alignment__) (NOLOAD) : { *(.debug_frame) }
  .debug_str       BLOCK(__section_alignment__) (NOLOAD) : { *(.debug_str) }
  .debug_loc       BLOCK(__section_alignment__) (NOLOAD) : { *(.debug_loc) }
  .debug_macinfo   BLOCK(__section_alignment__) (NOLOAD) : { *(.debug_macinfo) }

  /* SGI/MIPS DWARF 2 extensions. */
  .debug_weaknames ALIGN(__section_alignment__) (NOLOAD) : { *(.debug_weaknames) }
  .debug_funcnames ALIGN(__section_alignment__) (NOLOAD) : { *(.debug_funcnames) }
  .debug_typenames ALIGN(__section_alignment__) (NOLOAD) : { *(.debug_typenames) }
  .debug_varnames  ALIGN(__section_alignment__) (NOLOAD) : { *(.debug_varnames) }
  .debug_macro     ALIGN(__section_alignment__) (NOLOAD) : { *(.debug_macro) }

  /* DWARF 3 */
  .debug_ranges    ALIGN(__section_alignment__) (NOLOAD) : { *(.debug_ranges) }

  /* DWARF 4, merged back into .debug_info with DWARF 5 */
  .debug_types     ALIGN(__section_alignment__) (NOLOAD) : { *(.debug_types .gnu.linkonce.wt.*) }

  /* DWARF 5 */
  .debug_loclists  ALIGN(__section_alignment__) (NOLOAD) : { *(.debug_loclists) }
  .debug_rnglists  ALIGN(__section_alignment__) (NOLOAD) : { *(.debug_rnglists) }
  .debug_line_str  ALIGN(__section_alignment__) (NOLOAD) : { *(.debug_line_str) }
}
