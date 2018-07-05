extern bfd_boolean bfd_x86_elf_is_ulp_enabled
  (struct bfd *);

extern bfd_boolean bfd_x86_elf_setup_ulp
  (struct bfd_link_info *);

#define bfd_is_ulp_enabled bfd_x86_elf_is_ulp_enabled

#define bfd_setup_ulp bfd_x86_elf_setup_ulp

#define ULP_ENTRY_LEN 16
