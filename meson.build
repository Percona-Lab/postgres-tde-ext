pg_tde_sources = files(
        'src/access/pg_tdeam.c',
        'src/access/pg_tdeam_handler.c',
        'src/access/pg_tdeam_visibility.c',
        'src/access/pg_tdetoast.c',
        'src/access/pg_tde_io.c',
        'src/access/pg_tde_prune.c',
        'src/access/pg_tde_rewrite.c',
        'src/access/pg_tde_vacuumlazy.c',
        'src/access/pg_tde_visibilitymap.c',
        'src/encryption/enc_tuple.c',
)

incdir = include_directories('src')

pg_tde = shared_module('pg_tde',
  pg_tde_sources,
  c_pch: pch_postgres_h,
  kwargs: contrib_mod_args,
  include_directories: incdir,
)
contrib_targets += pg_tde

install_data(
  'pg_tde.control',
  'pg_tde--1.0.sql',
  kwargs: contrib_data_args,
)