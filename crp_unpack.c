/**************************************************************
* Lotus T4e (2008+) CRP file extractor
*
* (c) CyberNet, 2016
*
*
*/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <byteswap.h>
#include <strings.h>


// the XTEA 128bit key for T4E
uint32_t k[4]= {0x8fcb06da, 0xac193e62, 0x41500c5c, 0x64a7b1db };


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
  printf("./crp_unpack -f <CRP firmware file>\n");  
  printf("\n\n");
}

int main(int argc, char **argv)
{  
  uint32_t v[2], b[2], i[2], ps, p, q, c, s;  
  uint32_t *dbuffer_in;
  uint32_t *dbuffer_out;
  uint16_t t;
  uint16_t calc_crc=0;  
  uint16_t crp_crc=0;  
  int option = 0;
  uint8_t *crp_buffer;
  const char *crp_filename = NULL;
  const char bin_filename[32];
  uint32_t crp_filesize;
  uint8_t crp_chunks;
  uint32_t chunk_crp_size;
  uint32_t chunk_crp_offset;
  FILE *bin_file, *crp_file;


  opterr = 0;
  while ((option = getopt(argc, argv,"f:")) != -1) {
        switch (option) {                              
             case 'f' : crp_filename = optarg;
                 break;
             default: print_usage(); 
                 exit(EXIT_FAILURE);
        }
  }
  if (optind < argc || argc == 1) {    
    print_usage();
    exit(EXIT_FAILURE);
  }
    
  printf("Opening CRP File: '%s'\n", crp_filename);
  crp_file=fopen(crp_filename, "rb");
  if (!crp_file)
  {
    	printf("Unable to open file %s!\n", crp_filename);
    	return 1;
  }
  // get CRP size
  fseek(crp_file, 0, SEEK_END);
  crp_filesize=ftell(crp_file);
  fseek(crp_file, 0, SEEK_SET);
  crp_buffer=malloc(crp_filesize+1);
  // read CRP into buffer
  printf("Reading '%s' (%d) ... ", crp_filename, crp_filesize);
  fread(crp_buffer, crp_filesize, 1, crp_file);    
  printf("completed\n");
  // check CRP CRC vs Calculated CRC
  // CRC is just the uint16 sum of all bytes minus the last 2 ones
  p=0;
  q=crp_filesize-2;
  do {
      calc_crc += crp_buffer[p++];
      q--;
  } while (q);
  printf("Calculated CRC: 0x%04x - ", calc_crc);
  crp_crc= crp_buffer[crp_filesize-1]<<8 | crp_buffer[crp_filesize-2];  
  printf("File CRC: 0x%04x =>", crp_crc);
  if (crp_crc == calc_crc) printf(" MATCH\n");
  else 
  {
    printf(" NO MATCH\n");
    exit(-1);
  }
  // extract chunks and offsets in CRP file
  crp_chunks = (*(uint16_t*)crp_buffer);
  printf("CRP Chunks: %d\n", crp_chunks-1);  
  // extract information like start/length for the indidual chunks in the CRP file
  t = 1;
  do
  {
      chunk_crp_offset =  *(uint32_t*)(8*t+4+crp_buffer);
      printf("\nStart: 0x%x\n", chunk_crp_offset);
      chunk_crp_size =  *(uint32_t*)(8*t+8+crp_buffer);
      printf("Length: 0x%x\n", chunk_crp_size);
      ++t;
      // alloc buffers in/out
      dbuffer_in=malloc(chunk_crp_size);
      dbuffer_out=malloc(chunk_crp_size);      
      bzero(dbuffer_out, chunk_crp_size);
      // jump to firmware chunk in file
      // fill dbuffer_in with bitswapped 32bit blocks
      fseek(crp_file, chunk_crp_offset, SEEK_SET);
      fread(dbuffer_in, 1, chunk_crp_size, crp_file);  
      // adjust endianess in buffer        
      for ( c=0; c < chunk_crp_size/4; c++)
      {                
        dbuffer_in[c]=__bswap_32(dbuffer_in[c]);
      }      
      // for (c=0; c < chunk_crp_size/4; c++)
      //   printf("dbuffer_in[%d]: 0x%08x\n", c, dbuffer_in[c]);
      printf("deciphering [");
      fflush(stdout);
      i[0] = 0x0;
      i[1] = 0x0;  
      p= q = 0;
      s = chunk_crp_size;
      ps = chunk_crp_size / 8 / 10;
      while (s >= 8)
      {                
        if (s % ps == 0) { printf("X"); fflush(stdout); }
        b[0] = v[0]=dbuffer_in[p++];
        b[1] = v[1]=dbuffer_in[p++];
        xtea_decipher(0x20, v, k);     // XTEA
        v[0] = v[0] ^ i[0];
        v[1] = v[1] ^ i[1];
        i[0] = b[0];
        i[1] = b[1];
        dbuffer_out[q++] = v[0];
        dbuffer_out[q++] = v[1];
        s = s - 8;        
      }        
      printf("]\n");
      sprintf((char*)bin_filename, "out_%08x.bin", chunk_crp_offset);
      printf("Opening BIN output file: '%s'\n", bin_filename);
      bin_file = fopen(bin_filename, "wb");
      if (!bin_file)
      {
        printf("Unable to open file %s!\n", bin_filename);
        return -1;
      }
      printf("Writing '%s' (%d) ... ", bin_filename, chunk_crp_size);
      for ( c=0; c < chunk_crp_size/4; c++)
      {
        s=__bswap_32(dbuffer_out[c]);
        fwrite(&s, 4, 1, bin_file);
      }
      fclose(bin_file);
      printf("completed\n");

      //for (c=0; c < chunk_crp_size/4; c++)
      //  printf("dbuffer_out[%d]: 0x%08x\n", c, dbuffer_out[c]);


      // release memory of buffers
      free(dbuffer_in);
      free(dbuffer_out);
  } while (t < crp_chunks);
  printf("\n");
}

