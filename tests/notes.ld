ENTRY(_start)
SECTIONS
{
  /* Metadata sections */
  . = 0x400000 + SIZEOF_HEADERS;
  .interp            : { *(.interp) }
  .gnu.hash          : { *(.gnu.hash) }
  .dynsym            : { *(.dynsym) }
  .dynstr            : { *(.dynstr) }
  .gnu.version       : { *(.gnu.version) }
  .gnu.version_d     : { *(.gnu.version_d) }
  .gnu.version_r     : { *(.gnu.version_r) }
  .rela.dyn          : { *(.rela.*) }

  /* Executable sections */
  . = ALIGN(CONSTANT (COMMONPAGESIZE));
  .init              : { *(.init) }
  .plt               : { *(.plt) }
  .plt.got           : { *(.plt.got) }
  .plt.sec           : { *(.plt.sec) }
  .text              : { *(.text*) }
  .fini              : { *(.fini) }

  /* Read-only sections */
  . = ALIGN(CONSTANT (COMMONPAGESIZE));
  .rodata            : { *(.rodata*) }
  .eh_frame_hdr      : { *(.eh_frame_hdr) *(.eh_frame_entry*) }
  .eh_frame          : ONLY_IF_RO { *(.eh_frame) }

  /* Read-write sections */
  . = ALIGN(CONSTANT (COMMONPAGESIZE));
  .eh_frame          : ONLY_IF_RW { *(.eh_frame) }
  .init_array        : { *(.init_array) }
  .fini_array        : { *(.fini_array) }
  .got               : { *(.got) }
  .got.plt           : { *(.got.plt) }
  .data              : { *(.data*) }
  .bss               : { *(.bss*) *(.*bss) *(COMMON) }

  /* The DYNAMIC section */
  . = ALIGN(CONSTANT (COMMONPAGESIZE));
  .dynamic           : { *(.dynamic) }

  /* Manually select the order of notes sections */
  . = ALIGN(CONSTANT (COMMONPAGESIZE));
  .note.gnu.property : { *(.note.gnu.property) }
  . = ALIGN(CONSTANT (COMMONPAGESIZE));
  .note.gnu.build-id : { *(.note.gnu.build-id) }
  . = ALIGN(CONSTANT (COMMONPAGESIZE));
  .note.ABI-tag      : { *(.note.ABI-tag) }

  /DISCARD/          : { *(.note.*) *(.gnu.*) }

}
