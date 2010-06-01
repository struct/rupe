#!/usr/bin/env ruby

## Parse PE (Portable Executable) file format
## This file contains the necessary PE ruckus
## structures for parsing PE executables on
## Win32. Mostly useful for combining with
## ragweed, frasm or other small reversing tools.
##
## TODO:
##  - Proper constants (started)
##  - Real parsing helper methods such as 'PE::parse_image_shdr'
##  - Sanity checks
##  - Parse import tables
##  - Directory reading seems garbled on some binaries, produces
##    non-ascii strings. This needs to be investigated/fixed.

require 'ruckus'

class RUPE

    attr_accessor :pe_file, :dos_hdr, :coff, :peo, :data_dirs, :pe_shdrs

    def initialize(file)
        begin
            @pe_file = file
            @dat = File.read(file)
        rescue
            bail "Could not read [ #{pe_file} ]"
        end

        @pe_sig = PESig.new

        parse_dos_header
        parse_coff
        parse_opt_header

        @pe_shdrs = Array.new

        parse_pe_shdr
    end

    def get_file
        @dat.dup
    end

    def parse_dos_header
        @dos_hdr = DoSHeader.new
        f = get_file
        @dos_hdr.capture f[0, @dos_hdr.size.to_i]
    end

    def parse_coff
        @coff = CoffHeader.new
        f = get_file
        @coff.capture f[@dos_hdr.pe_offset.to_i + @pe_sig.size, @coff.size.to_i]
    end

    def parse_opt_header
        @peo = PEOptionalHeader.new
        f = get_file
        d = DataDirectory.new
        @peo.capture f[@dos_hdr.pe_offset.to_i + @pe_sig.size + @coff.size.to_i, @peo.size.to_i + (d.size * 16)]
        @data_dirs = @peo.dirs
    end

    def parse_pe_shdr
        0.upto(@coff.number_of_sections.to_i-1) do |i|
            shdr = ImageSectionHdr.new
            f = get_file
            shdr.capture f[@dos_hdr.pe_offset.to_i + @pe_sig.size + @coff.size.to_i + @coff.size_of_opt_header.to_i + (shdr.size.to_i * i), shdr.size.to_i]
            @pe_shdrs.push(shdr)
        end
    end

    def parse_imports
        d = @data_dirs[DataDirectoryTypes::IMPORT]
        i = ImageImportDescriptor.new
        0.upto(d.siz / i.size) do |c|
            f = get_file
            i = ImageImportDescriptor.new
            i.capture f[d.virtual_address + (c * i.size), i.size]
            puts i.to_human
        end
    end

    def parse_exports
        
    end

    class PESig < Ruckus::Structure
        str :pe_sig, :size => 4
    end

    class DoSHeader < Ruckus::Structure
        str   :mz_sig, :size => 2
        le16  :last_page_size
        le16  :file_num_pages
        le16  :num_reloc_items
        le16  :header_num_paragraphs
        le16  :min_extra_paragraphs
        le16  :max_extra_paragraphs
        le16  :initial_rel_ss
        le16  :initial_sp
        le16  :checksum
        le16  :initial_ip
        le16  :initial_rel_cs
        le16  :reloc_tbl_address
        le16  :overlay_num
        str   :rsvd1, :size => 8
        le16  :oem_id
        le16  :oem_info
        str   :rsvd2, :size => 20
        le32  :pe_offset
    end

    class ImageImportName < Ruckus::Structure
        le8     :hint
        le16    :nam    # hack
    end

    class ImageImportDescriptor < Ruckus::Structure
        le32    :orig_first_thunk
        le32    :time_date_stamp
        le32    :forward_chain
        le32    :nam
        le32    :first_thunk
    end

    ## AKA COFF
    class ImageSectionHdr < Ruckus::Structure
        str     :nam,   :size => 8
        le32    :virtual_address
#       le32    :physical_address
        le32    :virtual_size
        le32    :size_of_raw_data
        le32    :pointer_to_raw_data
        le32    :pointer_to_relocations
        le32    :pointer_to_line_numbers
        le16    :num_of_relocations
        le16    :num_of_line_numbers
        le32    :characteristics
    end

    class CoffHeader < Ruckus::Structure
        le16    :machine
        le16    :number_of_sections
        le32    :time_date_stamp
        le32    :pointer_to_symbol_table
        le32    :number_of_symbols
        le16    :size_of_opt_header
        le16    :characteristics
    end

    class DataDirectory < Ruckus::Structure
        le32    :virtual_address
        le32    :siz
    end

    class PEOptionalHeader < Ruckus::Structure
        le16 :magic
        byte :major_linker_ver
        byte :minor_linker_ver
        le32 :size_of_code
        le32 :size_of_initialized_data
        le32 :size_of_uninitialized_data
        le32 :address_of_entry_point
        le32 :base_of_code
        le32 :base_of_data
        le32 :image_base
        le32 :section_alignment
        le32 :file_alignment
        le16 :major_operating_system_version
        le16 :minor_operating_system_version
        le16 :major_image_version
        le16 :minor_image_version
        le16 :major_subsystem_version
        le16 :minor_subsystem_version
        le32 :reserved
        le32 :size_of_image
        le32 :size_of_headers
        le32 :check_sum
        le16 :subsystem
        le16 :dll_characteristics
        le32 :size_of_stack_reserve
        le32 :size_of_stack_commit
        le32 :size_of_heap_reserve
        le32 :size_of_heap_commit
        le32 :loader_flags
        le32 :number_of_rva_and_sizes
        vector :dirs, :class => DataDirectory, :count => 16
    end

    CPU_TYPES = {
        0 => :unspecified,
        0x014c => :i386,
        0x8664 => :amd64,
        0x01c0 => :arm,
        0x0162 => :r3000,
        0x0166 => :r4000,
        0x0168 => :r10000,
        0x0169 => :wcemipsv2,
        0x0184 => :alpha,
        0x01a2 => :sh3,
        0x01a3 => :sh3dsp,
        0x01a4 => :sh3e,
        0x01a6 => :sh4,
        0x01a8 => :sh5,
        0x01c2 => :thumb,
        0x01d3 => :am33,
        0x01f0 => :powerpc,
        0x01f1 => :powerpcfp,
        0x0200 => :ia64,
        0x0266 => :mips16,
        0x0284 => :alpha64,
        0x0366 => :mipsfpu,
        0x0466 => :mipsfpu16,
        0x0520 => :tricore,
        0x0cef => :cef,
        0x0ebc => :ebc,
        0x9041 => :m32r,
        0xc0ee => :cee,
      }

    SUBSYSTEMS = [
        :unspecified,
        :native,
        :windows_gui,
        :windows_console,
        nil,
        :os2_console,
        nil,
        :posix_console,
        :native_win9x_driver,
        :windows_ce_gui,
        :efi_application,
        :efi_boot_service_driver,
        :efi_runtime_driver,
        :efi_rom,
        :xbox,
      ]

    SECTION_FLAGS = [
        IMAGE_SCN_TYPE_NO_PAD          =      0x00000008, # Reserved.
        IMAGE_SCN_CNT_CODE             =      0x00000020, # Section contains code.
        IMAGE_SCN_CNT_INITIALIZED_DATA =      0x00000040, # Section contains initialized data.
        IMAGE_SCN_CNT_UNINITIALIZED_DATA =    0x00000080, # Section contains uninitialized data.
        IMAGE_SCN_LNK_OTHER            =      0x00000100, # Reserved.
        IMAGE_SCN_LNK_INFO             =      0x00000200, # Section contains comments or some  other type of information.
        IMAGE_SCN_LNK_REMOVE           =      0x00000800, # Section contents will not become part of image.
        IMAGE_SCN_LNK_COMDAT           =      0x00001000, # Section contents comdat.
        IMAGE_SCN_NO_DEFER_SPEC_EXC    =      0x00004000, # Reset speculative exceptions handling bits in the TLB entries for this section.
        IMAGE_SCN_GPREL                =      0x00008000, # Section content can be accessed relative to GP
        IMAGE_SCN_MEM_FARDATA          =      0x00008000,
        IMAGE_SCN_MEM_PURGEABLE        =      0x00020000,
        IMAGE_SCN_MEM_16BIT            =      0x00020000,
        IMAGE_SCN_MEM_LOCKED           =      0x00040000,
        IMAGE_SCN_MEM_PRELOAD          =      0x00080000,
        IMAGE_SCN_ALIGN_1BYTES         =      0x00100000,
        IMAGE_SCN_ALIGN_2BYTES         =      0x00200000,
        IMAGE_SCN_ALIGN_4BYTES         =      0x00300000, 
        IMAGE_SCN_ALIGN_8BYTES         =      0x00400000, 
        IMAGE_SCN_ALIGN_16BYTES        =      0x00500000, 
        IMAGE_SCN_ALIGN_32BYTES        =      0x00600000, 
        IMAGE_SCN_ALIGN_64BYTES        =      0x00700000, 
        IMAGE_SCN_ALIGN_128BYTES       =      0x00800000, 
        IMAGE_SCN_ALIGN_256BYTES       =      0x00900000, 
        IMAGE_SCN_ALIGN_512BYTES       =      0x00A00000, 
        IMAGE_SCN_ALIGN_1024BYTES      =      0x00B00000, 
        IMAGE_SCN_ALIGN_2048BYTES      =      0x00C00000, 
        IMAGE_SCN_ALIGN_4096BYTES      =      0x00D00000, 
        IMAGE_SCN_ALIGN_8192BYTES      =      0x00E00000, 
        IMAGE_SCN_ALIGN_MASK           =      0x00F00000,
        IMAGE_SCN_LNK_NRELOC_OVFL      =      0x01000000, # Section contains extended relocations.
        IMAGE_SCN_MEM_DISCARDABLE      =      0x02000000, # Section can be discarded.
        IMAGE_SCN_MEM_NOT_CACHED       =      0x04000000, # Section is not cachable.
        IMAGE_SCN_MEM_NOT_PAGED        =      0x08000000, # Section is not pageable.
        IMAGE_SCN_MEM_SHARED           =      0x10000000, # Section is shareable.
        IMAGE_SCN_MEM_EXECUTE          =      0x20000000, # Section is executable.
        IMAGE_SCN_MEM_READ             =      0x40000000, # Section is readable.
        IMAGE_SCN_MEM_WRITE            =      0x80000000  # Section is writeable.
    ]

    class DataDirectoryTypes
        EXPORT = 0
        IMPORT = 1
        RESOURCE = 2
        EXCEPTION = 3
        CERTIFICATE_FILE = 4
        RELOCATION_TABLE = 5
        DEBUG_DATA = 6
        ARCH_DATA = 7
        GLOBAL_PTR = 8
        TLS_TABLE = 9
        LOAD_CONFIG_TABLE = 10
        BOUND_IMPORT_TABLE = 11
        IMPORT_ADDRESS_TABLE = 12
        DELAY_IMPORT_DESC = 13
        COM_RUNTIME_HDR = 14
        RESERVED = 15
    end
end

if $0 == __FILE__

    p = RUPE.new(ARGV[0])

    puts "\n; DOS HEADER -----------------------------------\n\n"
    puts p.dos_hdr.to_human

    puts "\n; PE IMAGE FILE HEADER (COFF) -----------------------------------\n\n"
    puts p.coff.to_human

    puts "\n; PE OPTIONAL HEADER -------------------------------------\n\n"
    puts p.peo.to_human

    puts "\n; DATA DIRECTORIES ---------------------------------------\n\n"
    p.data_dirs.each do |x| puts x.to_human end

    puts "\n; SECTION HEADERS ----------------------------------------\n\n"
    p.pe_shdrs.each do |x| puts x.to_human end

    p.parse_imports
    
end
