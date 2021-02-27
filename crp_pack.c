/**************************************************************
* Lotus T4e (2008+) CRP file packer
*
* (c) CyberNet <cn@warp.at>, 2016
*
* 29/05/2016 * added -s, -c, -h options
* 25/06/2016 * added -a, auto padding options
* 30/07/2016 * automaticially determine BIN file size and needed FLASH size aligned to 8 bytes
* 04/08/2016 * auto max size for 0x10000/0x20000 addresses
*/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>

#ifdef __APPLE__
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>
#define __bswap_32(x) OSSwapInt32(x)
#else
#include <byteswap.h>
#endif

// the XTEA 128bit key for T4E
uint32_t k[4]= {0x8fcb06da, 0xac193e62, 0x41500c5c, 0x64a7b1db };
const unsigned char t4e_str[] = "T4E                             ";

struct t4e_canbootldr_hdr {
      int8_t        unkn_xtea_init[8];      // first round of xtea data ?
      int32_t       len_hdr_data;           // len_data+0x40
      unsigned char t4e[32];                // fixed string used by bootloader
      int32_t       flash_addr;             // destination flash addr in MPC563
      int32_t       len_data;               // len of the payload excluding the can_hdr
      int32_t       unkn1;                  // unknown 0xA00 related - min bootldr version ?
      int32_t       unkn2;                  // unknown 0xA00 related - max bootldr version ?
      unsigned char null[16];               // 16 NULL padding bytes
} can_hdr;


void xtea_encipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    for (i=0; i < num_rounds; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    }
    v[0]=v0; v[1]=v1;
}

void xtea_decipher(unsigned int num_rounds, uint32_t v[2], uint32_t const key[4]) {
    unsigned int i;
    uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    for (i=0; i < num_rounds; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}

void print_usage(void)
{
  printf("\n\n");
  printf("./crp_pack -f <BIN file> [-s <Flash size>] -a 0x<Flash addr> -c <CRP file> [-h]\n\n");  
  printf(" -f <BIN file>\n");
  printf("    Binary file that should be encrypted\n\n");  
  printf(" -s <Flash size>\n");
  printf("    Size in bytes to flash to the ECU (OPTIONAL otherwise BIN file size is used)\n\n");
  printf(" -a 0x<Flash address>\n");
  printf("    Destination address in the ECU - 0x10000 for calibration, 0x20000 for programm data (HEX value)\n\n");
  printf(" -c <CRP file>\n");
  printf("    Output CRP filename\n\n");
  printf(" -h \n");
  printf("    If specified creates a T4e CAN bootldr compatible header is prefixed prior encryption\n\n");  
  printf("\n\n");
}

int main(int argc, char **argv)
{  
  uint32_t v[2], i[2], p, q, c, s;  
  uint32_t *dbuffer_in;
  uint32_t *dbuffer_out;  
  int option = 0;
  uint8_t *bin_buffer;
  const char *bin_filename = NULL;
  const char *crp_filename = NULL;
  uint32_t bin_filesize;  
  uint32_t flash_size=0;
  uint32_t flash_addr=0;
  uint32_t hdr_size=0;
  uint32_t do_header=0;
  uint8_t  padding_size=0;
  uint8_t  padding_offset=0;
  FILE *bin_file, *crp_file;


  opterr = 0;
  while ((option = getopt(argc, argv,"f:s:a:c:s:h")) != -1) {
        switch (option) {                              
             case 'f' : bin_filename = optarg;
                 break;            
             case 'a' : flash_addr = (int32_t)strtol(optarg, NULL, 16);
                 break;
             case 's' : flash_size = (int32_t)strtol(optarg, NULL, 10);
                 break;
             case 'c' : crp_filename = optarg;
                 break;
             case 'h' : do_header = 1;
                 break;
             default: print_usage(); 
                 exit(EXIT_FAILURE);
        }
  }
   
  if (bin_filename == NULL)
  {
    printf("\n *** ERROR - no BIN file given\n");
    print_usage();
    exit(EXIT_FAILURE);
  }
  if (crp_filename == NULL)
  {
    printf("\n *** ERROR - no CRP file given\n");
    print_usage();
    exit(EXIT_FAILURE);
  }
  if ((flash_addr != 0x10000) && (flash_addr != 0x20000))
  {
    printf("\n *** ERROR - unknown flash address given\n");
    print_usage();
    exit(EXIT_FAILURE);
  }
  printf("Opening .BIN File: '%s'\n", bin_filename);
  bin_file=fopen(bin_filename, "rb");
  if (!bin_file)
  {
    	printf("\n *** ERROR - Unable to open file %s!\n", bin_filename);
    	return 1;
  }


  ////////////////////////////////
  // get BIN size
  ////////////////////////////////
  fseek(bin_file, 0, SEEK_END);
  bin_filesize=ftell(bin_file);  
  fseek(bin_file, 0, SEEK_SET);
  if ((flash_size>0) && (bin_filesize > flash_size))
  {
    printf("\n *** WARNING - given Flash Size is less than .BIN size, truncating .BIN data ...\n");
  }
  else if (flash_size > bin_filesize)
  {
    printf("\n *** WARNING - given Flash Size is bigger than .BIN size, using all available .BIN data ...\n");
    flash_size=bin_filesize;
  }
  else
  {
    printf("\n *** WARNING - no Flash Size given, using .BIN size ...\n");
    flash_size=bin_filesize;
  }

  if ((flash_addr == 0x20000) && (flash_size > 0x5FFFE))
  {
    printf("\n *** WARNING - Flash Size for Flash destination addr==0x20000 can be a max of 0x5FFFE bytes, adjusting ...\n");
    flash_size=0x5FFFE;
  }
  if ((flash_addr == 0x10000) && (flash_size > 0xC000))
  {
    printf("\n *** WARNING - Flash Size for Flash destination addr==0x10000 can be a max of 0xC000 bytes, adjusting ...\n");
    flash_size=0xC000;
  }

  //////////////////////////////////////////////////////
  // the flash_size always needs to be 2 byte aligned
  //////////////////////////////////////////////////////
  padding_offset = flash_size % 2;   
  if (padding_offset)
  {
      printf("\n *** WARNING - Flash Size needs to be a multiple of 2 (adjusting) ...\n");
      if (bin_filesize > flash_size)
      {
        flash_size++; // adjusting upwards, because we have the BIN data to do it
      }
      else
      {
        flash_size--; // adjusting downwards, because our BIN is not big enough
      }      
  }

  ////////////////////////////////
  // init header if we need it
  ////////////////////////////////
  if (do_header)
  {
      hdr_size = sizeof(can_hdr);      
      padding_offset = (flash_size + hdr_size) % 8;      
      // if we generate a header for T4E bootloaders
      // we need to make sure that the resulting (hdr+flash_size) is padded to 4 bytes
      if (padding_offset)
      {
        padding_size=8-padding_offset;        
        flash_size+=padding_size;      
      }      

      bzero(&can_hdr, sizeof(can_hdr));
      memcpy(&can_hdr.t4e, &t4e_str, 32);
      can_hdr.len_data = __bswap_32(flash_size-padding_size);
      can_hdr.len_hdr_data = __bswap_32(flash_size+0x40-padding_size);
      can_hdr.flash_addr = __bswap_32(flash_addr);   
      can_hdr.unkn_xtea_init[0]=0x25;
      can_hdr.unkn_xtea_init[1]=0x36;
      can_hdr.unkn_xtea_init[2]=0xad;
      can_hdr.unkn_xtea_init[3]=0x49;
      can_hdr.unkn_xtea_init[4]=0x79;
      can_hdr.unkn_xtea_init[5]=0x5c;
      can_hdr.unkn_xtea_init[6]=0x86;
      can_hdr.unkn_xtea_init[7]=0x7a;
      printf("Creating T4e CAN Bootloader compatible header (%d/0x%X bytes)\n", hdr_size, hdr_size);
      printf("  \\_ Payload length: %d/0x%X\n", __bswap_32(can_hdr.len_data), __bswap_32(can_hdr.len_data));      
      printf("  \\_ Flash addr: 0x%X\n", flash_addr);
      // printf("  \\_ 8-Byte Aligned Flash Size: %d/0x%X\n", flash_size, flash_size);      
  }
 
 
  ////////////////////////////////
  // read BIN into buffer
  ////////////////////////////////
  bin_buffer=malloc(flash_size);             // flash_size includes any padding needed (calc above)
  memset(bin_buffer, 0xFF, flash_size);      // fill with 0xFF - so that any leftover bytes not read from BIN will be padded with 0xFF
  printf("Reading '%s' (%d) ... ", bin_filename, flash_size);
  fread(bin_buffer, 1, flash_size, bin_file);    
  printf("completed\n");
  printf("Encrypting %d (HDR+BIN+Padding) ... ", flash_size+hdr_size);
  dbuffer_in=malloc(flash_size+hdr_size);
  dbuffer_out=malloc(flash_size+hdr_size);     
  bzero(dbuffer_out, flash_size+hdr_size);
 
  // -h enabled
  if (hdr_size > 0)
  {
      memcpy(dbuffer_in, &can_hdr, hdr_size);
      memcpy(dbuffer_in+(hdr_size/4), bin_buffer, flash_size);      
  }
  else
  // dont add (-h)eader
  {
      memcpy(dbuffer_in, bin_buffer, flash_size);  
  }

  // fix endianess of data before encrypting
  for ( c=0; c < (flash_size+hdr_size)/4; c++)
  {
      dbuffer_in[c]=__bswap_32(dbuffer_in[c]);      
  }


  /*
  for (s=0;s<(flash_size+hdr_size)/4;s++)
  {
    printf("0x%x -> 0x%08x\n", s*4, __bswap_32(dbuffer_in[s]));
  }
  */
  

  printf("encrypting [");
  fflush(stdout);

  i[0] = 0x0;
  i[1] = 0x0;  
  p= q = 0;
  s = flash_size+hdr_size;
  // ps = flash_size / 8 / 10;
  while (s >= 8)
  {                
      if (s % 8000 == 0) { printf("X"); fflush(stdout); }
      v[0] = dbuffer_in[p++];
      v[1] = dbuffer_in[p++];
      v[0] = v[0] ^ i[0];
      v[1] = v[1] ^ i[1];
      xtea_encipher(0x20, v, k);     // XTEA 
      i[0] = v[0];
      i[1] = v[1];
      dbuffer_out[q++] = v[0];
      dbuffer_out[q++] = v[1];
      s = s - 8;        
  }        
  printf("]\n");
  
  printf("Opening CRP output file: '%s'\n", crp_filename);
  crp_file = fopen(crp_filename, "wb");
  if (!crp_file)
  {
    printf("Unable to open file %s!\n", crp_filename);
    return -1;
  }
  printf("Writing '%s' (%d) ... ", crp_filename, flash_size+hdr_size);
  for ( c=0; c < (flash_size+hdr_size)/4; c++)
  {
      s=__bswap_32(dbuffer_out[c]);
      fwrite(&s, 4, 1, crp_file);
  }
  fclose(crp_file);
  printf("completed\n");
  
  free(dbuffer_in);
  free(dbuffer_out);
  printf("\n");
}

