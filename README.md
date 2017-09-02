OZF decoder DLL library
=============

void*	ozf_open(char* path);
void	ozf_get_tile(map_stream* s, int scale, int x, int y, unsigned char* data);
int		ozf_num_scales(map_stream* s);
int		ozf_num_tiles_per_x(map_stream*, int scale);
int		ozf_num_tiles_per_y(map_stream*, int scale);
int		ozf_scale_dx(map_stream*, int scale);
int		ozf_scale_dy(map_stream*, int scale);
void	ozf_close(map_stream*);
