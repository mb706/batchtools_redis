source("renv/activate.R")
Sys.setenv(OMP_NUM_THREADS="1")
Sys.setenv(OPENBLAS_NUM_THREADS="1")
Sys.setenv(MKL_NUM_THREADS="1")
try(data.table::setDTthreads(1))
try(RhpcBLASctl::blas_set_num_threads(1L))
try(RhpcBLASctl::omp_set_num_threads(1L))

