/**
 * swampex, a map processing library
 *
 * Authors: 
 *
 * Daniil Smelov <dn.smelov@gmail.com>
 *
 * Copyright (C) 2006-2009 Daniil Smelov, Slava Baryshnikov
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */

#include <stdlib.h>
#include <stdio.h>
#include <zlib.h>
#include <string.h>

#define EXPORT __declspec(dllexport)
#include "ozf_decoder.h"

#ifdef WIN32
#include <malloc.h>
#endif

#define OZFX3_KEY_MAX				256
#define OZFX3_MAGIC_OFFSET_0		14
#define OZFX3_MAGIC_OFFSET_1		165
#define OZFX3_MAGIC_OFFSET_2		0xA2
#define OZFX3_MAGIC_BLOCKLENGTH_0	150
#define OZFX3_KEY_BLOCK_SIZE		4

#define D0_KEY_CYCLE					0xD
#define D1_KEY_CYCLE					0x1A
#define OZFX3_ZDATA_ENCRYPTION_LENGTH	16

#define	OZF_TILE_WIDTH				64
#define	OZF_TILE_HEIGHT				64

static unsigned char d0_key[] =
{
	0x2D, 0x4A, 0x43, 0xF1, 0x27, 0x9B, 0x69, 0x4F,
	0x36, 0x52, 0x87, 0xEC, 0x5F, 0x8D, 0x40, 0 
};

static unsigned char d1_key[] =
{
	0x2D, 0x4A, 0x43, 0xF1, 0x27, 0x9B, 0x69, 0x4F,
	0x36, 0x52, 0x87, 0xEC, 0x5F, 0x42, 0x53, 0x22,
	0x9E, 0x8B, 0x2D, 0x83, 0x3D, 0xD2, 0x84, 0xBA,
	0xD8, 0x5B, 0x8B, 0xC0
};

int ozf_decompress_tile(Bytef *dest, uLongf* destLen, const Bytef *source, uLong sourceLen)
{
    z_stream stream;
    int err;

    stream.next_in = (Bytef*)source;
    stream.avail_in = (uInt)sourceLen;
	
    if ((uLong)stream.avail_in != sourceLen) 
		return Z_BUF_ERROR;

    stream.next_out = dest;
    stream.avail_out = (uInt)*destLen;
    
	if ((uLong)stream.avail_out != *destLen) 
		return Z_BUF_ERROR;

    stream.zalloc = (alloc_func)0;
    stream.zfree = (free_func)0;

    err = inflateInit(&stream);
    
	if (err != Z_OK) 
		return err;

    err = inflate(&stream, Z_FINISH);

    if (err != Z_STREAM_END) 
	{
        inflateEnd(&stream);
        return err == Z_OK ? Z_BUF_ERROR : err;
    }
    
	*destLen = stream.total_out;

    err = inflateEnd(&stream);
	
    return err;
}

void ozf_decode0(unsigned char *s, long n, unsigned char initial)
{
	long j;
	for(j = 0; j < n; j++)
	{
		long k = j % D0_KEY_CYCLE;
		unsigned char c		= d0_key[k];
		c += initial;
		unsigned char c1	= s[j];
		c ^= c1;
		s[j] = c;
	}
}

void ozf_decode1(unsigned char *s, long n, unsigned char initial)
{
	long j;
	for(j = 0; j < n; j++)
	{
		long k = j % D1_KEY_CYCLE;
		unsigned char c		= d1_key[k];
		c += initial;
		unsigned char c1	= s[j];
		c ^= c1;
		s[j] = c;
	}
}

unsigned long ozf_calculate_key(FILE* fp)
{
	unsigned long key = 0;
	unsigned char initial = 0;
	unsigned char keyblock[OZFX3_KEY_BLOCK_SIZE];
	unsigned char bytes_per_info = 0;

	fseek(fp, OZFX3_MAGIC_OFFSET_0, SEEK_SET);
	fread(&bytes_per_info, 1, 1, fp);

	unsigned long offset = OZFX3_MAGIC_OFFSET_2;
	fseek(fp, offset, SEEK_SET);
	fread(&initial, 1, 1, fp);

	offset = OZFX3_MAGIC_OFFSET_1 + bytes_per_info - OZFX3_MAGIC_BLOCKLENGTH_0;
	fseek(fp, offset, SEEK_SET);
	fread(keyblock, OZFX3_KEY_BLOCK_SIZE, 1, fp);

	ozf_decode1(keyblock, OZFX3_KEY_BLOCK_SIZE, initial);

	switch (keyblock[0])
	{
		case 0xf1:
			initial +=0x8a;
			break;
		case 0x18:
		case 0x54:
			initial +=0xa0;
			break;
		case 0x56:
			initial +=0xb9;
			break;
		case 0x43:
			initial +=0x6a;
			break;
		case 0x83:
			initial +=0xa4;
			break;
		case 0xc5:
			initial +=0x7e;
			break;
		case 0x38:
			initial +=0xc1;
			break;
		default:
			break;
	}

	key = initial;
	return key;
}

long ozf_get_encyption_depth(void *data, long size, unsigned long key)
{
	long	nEncryptionDepth = -1;

	void*	p = malloc(size);
	unsigned long nDecompressed = OZF_TILE_WIDTH * OZF_TILE_HEIGHT;
	
	void* pDecompressed = (void*)malloc(nDecompressed);

	long i;
	for ( i = 4; i <= size; i++)
	{
		memcpy(p, data, size);
		ozf_decode1((unsigned char*)p, i, key);

		long err = ozf_decompress_tile((Bytef*)pDecompressed, (uLongf*)&nDecompressed, (const Bytef*)p, (uLong)size);

		nEncryptionDepth = i;

		if ( err == Z_OK )
			break;
	}

	free(p);
	free(pDecompressed);

	if ( nEncryptionDepth == size)
		nEncryptionDepth = -1;

	return nEncryptionDepth;
}

void ozf_init_encrypted_stream(map_stream* stream)
{
	ozf_stream* s = (ozf_stream*)stream;
	unsigned char bytes_per_infoblock;
	unsigned long offset;
	unsigned long scales_table_offset;
	int i, j;

	fseek(s->file, OZFX3_MAGIC_OFFSET_0, SEEK_SET);
	fread(&bytes_per_infoblock, 1, 1, s->file);

	offset =	OZFX3_MAGIC_OFFSET_1 + bytes_per_infoblock - 
				OZFX3_MAGIC_BLOCKLENGTH_0 + sizeof(long);

	s->ozf3 = (ozf3_header*)malloc(sizeof(ozf3_header));
	
	fseek(s->file, offset, SEEK_SET);
	
	fread(&s->ozf3->size, sizeof(long), 1, s->file);
	fread(&s->ozf3->width, sizeof(long), 1, s->file);
	fread(&s->ozf3->height, sizeof(long), 1, s->file);
	fread(&s->ozf3->depth, sizeof(short), 1, s->file);
	fread(&s->ozf3->bpp, sizeof(short), 1, s->file);

	ozf_decode1((unsigned char*)s->ozf3, sizeof(ozf3_header), s->key);

	offset = s->size - sizeof(long);
	
	fseek(s->file, offset, SEEK_SET);
	fread(&scales_table_offset, sizeof(long), 1, s->file);
	
	ozf_decode1((unsigned char*)&scales_table_offset, sizeof(long), s->key);

 	s->scales = (s->size - scales_table_offset - sizeof(long)) / sizeof(long);

	s->scales_table = 
		(unsigned long*)malloc(s->scales * sizeof(unsigned long));
		
	s->images = 
		(ozf_image*)malloc(s->scales * sizeof(ozf_image));

	fseek(s->file, scales_table_offset, SEEK_SET);
	fread(s->scales_table, s->scales * sizeof(long), 1, s->file);
	
	for (i = 0; i < s->scales; i++)
	{
		unsigned char* tile;
	
		ozf_decode1((unsigned char*)&s->scales_table[i], sizeof(long), s->key);

		fseek(s->file, s->scales_table[i], SEEK_SET);
		
		fread(&s->images[i].header.width, sizeof(long), 1, s->file);
		fread(&s->images[i].header.height, sizeof(long), 1, s->file);
		fread(&s->images[i].header.xtiles, sizeof(short), 1, s->file);
		fread(&s->images[i].header.ytiles, sizeof(short), 1, s->file);
		fread(s->images[i].header.palette, sizeof(long)*256, 1, s->file);

		ozf_decode1((unsigned char*)&s->images[i].header.width, sizeof(long), s->key);
		ozf_decode1((unsigned char*)&s->images[i].header.height, sizeof(long), s->key);
		ozf_decode1((unsigned char*)&s->images[i].header.xtiles, sizeof(short), s->key);
		ozf_decode1((unsigned char*)&s->images[i].header.ytiles, sizeof(short), s->key);
		ozf_decode1((unsigned char*)s->images[i].header.palette, 1024, s->key);
	
		s->images[i].tiles = s->images[i].header.xtiles * s->images[i].header.ytiles + 1;
		
		s->images[i].tiles_table = 
			(unsigned long*)malloc(s->images[i].tiles * sizeof(long));
		
		fread(s->images[i].tiles_table, s->images[i].tiles * sizeof(long), 1, s->file);
		
		for (j = 0; j < s->images[i].tiles; j++)
		{
			unsigned long* p = &s->images[i].tiles_table[j];
			
			ozf_decode1((unsigned char*)p, sizeof(long), s->key);
		}
						
		unsigned long tilesize =	s->images[i].tiles_table[1] - 
									s->images[i].tiles_table[0];

				
		tile = (unsigned char*)malloc(tilesize);
		
		fseek(s->file, s->images[i].tiles_table[0], SEEK_SET);
		fread(tile, tilesize, 1, s->file);
											
		s->images[i].encryption_depth = 
			ozf_get_encyption_depth(tile, tilesize, s->key);
					
		free(tile);									
	}

}

void ozf_init_raw_stream(map_stream* stream)
{
	ozf_stream* s = (ozf_stream*)stream;

	unsigned long offset;
	unsigned long scales_table_offset;
	int i, j;

	offset = 0;

	s->ozf2 = (ozf2_header*)malloc(sizeof(ozf2_header));
	
	fseek(s->file, offset, SEEK_SET);
	
	fread(&s->ozf2->magic, sizeof(short), 1, s->file); 
	fread(&s->ozf2->dummy1, sizeof(long), 1, s->file);
	fread(&s->ozf2->dummy2, sizeof(long), 1, s->file);
	fread(&s->ozf2->dummy3, sizeof(long), 1, s->file);
	fread(&s->ozf2->dummy4, sizeof(long), 1, s->file);

	fread(&s->ozf2->width, sizeof(long), 1, s->file);
	fread(&s->ozf2->height, sizeof(long), 1, s->file);

	fread(&s->ozf2->depth, sizeof(short), 1, s->file);
	fread(&s->ozf2->bpp, sizeof(short), 1, s->file);

	fread(&s->ozf2->dummy5, sizeof(long), 1, s->file);

	fread(&s->ozf2->memsiz, sizeof(long), 1, s->file); 

	fread(&s->ozf2->dummy6, sizeof(long), 1, s->file); 
	fread(&s->ozf2->dummy7, sizeof(long), 1, s->file); 
	fread(&s->ozf2->dummy8, sizeof(long), 1, s->file); 
	fread(&s->ozf2->version, sizeof(long), 1, s->file); 

	offset = s->size - sizeof(long);
	
	fseek(s->file, offset, SEEK_SET);
	fread(&scales_table_offset, sizeof(long), 1, s->file);

 	s->scales = (s->size - scales_table_offset - sizeof(long)) / sizeof(long);

	s->scales_table = 
		(unsigned long*)malloc(s->scales * sizeof(unsigned long));
		
	s->images = 
		(ozf_image*)malloc(s->scales * sizeof(ozf_image));

	fseek(s->file, scales_table_offset, SEEK_SET);
	fread(s->scales_table, s->scales * sizeof(long), 1, s->file);
	
	for (i = 0; i < s->scales; i++)
	{
		unsigned char* tile;

		fseek(s->file, s->scales_table[i], SEEK_SET);
		
		fread(&s->images[i].header.width, sizeof(long), 1, s->file);
		fread(&s->images[i].header.height, sizeof(long), 1, s->file);
		fread(&s->images[i].header.xtiles, sizeof(short), 1, s->file);
		fread(&s->images[i].header.ytiles, sizeof(short), 1, s->file);
		fread(s->images[i].header.palette, sizeof(long)*256, 1, s->file);

		s->images[i].tiles = s->images[i].header.xtiles * s->images[i].header.ytiles + 1;
		
		s->images[i].tiles_table = 
			(unsigned long*)malloc(s->images[i].tiles * sizeof(long));
		
		fread(s->images[i].tiles_table, s->images[i].tiles * sizeof(long), 1, s->file);

	}
}

void ozf_get_tile(map_stream* stream, int scale, int x, int y, unsigned char* data)
{
	ozf_stream* s = (ozf_stream*)stream;

	long j;
	
	if (scale > s->scales - 1)
		return;
	
	if (x > s->images[scale].header.xtiles - 1)
		return;

	if (y > s->images[scale].header.ytiles - 1)
		return;
		
	if (x < 0)
		return;

	if (y < 0)
		return;
	
	long i = y * s->images[scale].header.xtiles + x;
		
	unsigned long tilesize =	s->images[scale].tiles_table[i+1] - 
								s->images[scale].tiles_table[i];

	unsigned char* tile = (unsigned char*)alloca(tilesize);
		
	fseek(s->file, s->images[scale].tiles_table[i], SEEK_SET);
	fread(tile, tilesize, 1, s->file);
	
	if (s->type == OZF_STREAM_ENCRYPTED)
	{
		if (s->images[scale].encryption_depth == -1)
			ozf_decode1(tile, tilesize, s->key);
		else
			ozf_decode1(tile, s->images[scale].encryption_depth, s->key);
	}
	
	if (!(tile[0] == 0x78 && tile[1] == 0xda))  // zlib signature
	{
		return;
	}
		
	unsigned long	decompressed_size = OZF_TILE_WIDTH * OZF_TILE_HEIGHT;
	unsigned char*	decompressed = (unsigned char*)alloca(decompressed_size);

	long n = ozf_decompress_tile((Bytef*)decompressed, (uLongf*)&decompressed_size,
			(const Bytef*)tile, (uLong)tilesize);
								
	unsigned char*	foo = data;
	unsigned char*	palette = (unsigned char*)s->images[scale].header.palette;

	for(j = 0; j < OZF_TILE_WIDTH * OZF_TILE_HEIGHT; j++)
	{
		unsigned char c = decompressed[j];

		int tile_y = (OZF_TILE_WIDTH - 1) - (j / OZF_TILE_WIDTH);
		int tile_x = j % OZF_TILE_WIDTH;
		int tile_z = tile_y * OZF_TILE_WIDTH + tile_x;
				
		unsigned char r = palette[c*4 + 2];
		unsigned char g = palette[c*4 + 1];
		unsigned char b = palette[c*4 + 0];
		unsigned char a = 255;

		data[tile_z * 4 + 0] = r;
		data[tile_z * 4 + 1] = g;
		data[tile_z * 4 + 2] = b;
		data[tile_z * 4 + 3] = a;
	}
}

int	ozf_num_scales(map_stream* stream)
{
	ozf_stream* s = (ozf_stream*)stream;

	return s->scales - 1;
}

int	ozf_num_tiles_per_x(map_stream* stream, int scale)
{
	ozf_stream* s = (ozf_stream*)stream;

	return s->images[scale].header.xtiles;
}

int	ozf_num_tiles_per_y(map_stream* stream, int scale)
{
	ozf_stream* s = (ozf_stream*)stream;

	return s->images[scale].header.ytiles;
}

int	ozf_scale_dx(map_stream* stream, int scale)
{
	ozf_stream* s = (ozf_stream*)stream;

	return s->images[scale].header.width;
}

int	ozf_scale_dy(map_stream* stream, int scale)
{
	ozf_stream* s = (ozf_stream*)stream;

	return s->images[scale].header.height;
}

map_stream* ozf_open(char* path)
{
	ozf_stream* s = NULL;
	
	FILE* f = fopen(path, "rb");

	if (f)
	{
		s = (ozf_stream*)malloc(sizeof(ozf_stream));
		memset(s, 0, sizeof(ozf_stream));
		
		s->file = f;
		s->type = OZF_STREAM_DEFAULT;
		fseek(f, 0, SEEK_END);
		s->size = ftell(f);
	
		if (strstr(path, ".ozfx3"))
		{

			s->type = OZF_STREAM_ENCRYPTED;
			s->key	= ozf_calculate_key(s->file);

			ozf_init_encrypted_stream(s);			
		}
		else
		if (strstr(path, ".ozf2"))
		{
			ozf_init_raw_stream(s);			
		}
	}
	
	return (map_stream*)s;
}

void ozf_close(map_stream* stream)
{
	ozf_stream* s = (ozf_stream*)stream;

	if (s)
	{
		if (s->file)
		{
			fclose(s->file);
		}

		if (s->ozf2)
			free(s->ozf2);

		if (s->ozf3)
			free(s->ozf3);

		if (s->scales_table)
			free(s->scales_table);
			
		if (s->images)
		{
			int i;
			for (i = 0; i < s->scales; i++)
			{
				free(s->images[i].tiles_table);
			}
			free(s->images);
		}
		free(s);
	}
}
