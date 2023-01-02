#ifndef FEC_BASE_H
#define FEC_BASE_H

#include <cstdint>

typedef uint8_t gf;


/**
 * NEON / SSE3 optimized version of https://github.com/OpenHD/Open.HD/blob/8f7be98a3b7c97f325ae655256c81bea09199834/wifibroadcast-base/fec.c
 * NOTE: fec_init is not needed anymore - the gf256 values are precomputed and stored in the header(s) of optimized -
 * and the block size / n data / n fec blocks is variable (note: for each sequence of blocks, the encode / decode params need to match though).
 * First part of this file mostly matches the original fec impl, second part is mostly new / was created during the libmoepgf refactoring.
 */

/**
 * @param blockSize size of each block (all blocks must have the same size)
 * @param data_blocks array of pointers to the memory of the data blocks
 * @param nrDataBlocks how many data blocks
 * @param fec_blocks array of pointers to the memory of the fec blocks (generated)
 * @param nrFecBlocks how many fec blocks to generate
 */
void fec_encode(unsigned int blockSize,
                const gf **data_blocks,
                unsigned int nrDataBlocks,
                gf **fec_blocks,
                unsigned int nrFecBlocks);

/**
 *
 * @param blockSize size of each block
 * @param data_blocks array of pointers to the memory of the data blocks. Missing areas will be filled
 * @param nr_data_blocks how many data blocks (available and missing)
 * @param fec_blocks array of pointers to the memory of the fec blocks
 * @param fec_block_nos indices of the received fec blocks
 * @param erased_blocks indices of the erased / missing data blocks that will be reconstructed
 * @param nr_fec_blocks how many data blocks were erased - need at least this many fec blocks.
 */
void fec_decode(unsigned int blockSize,
                gf **data_blocks,
                unsigned int nr_data_blocks,
                gf **fec_blocks,
                const unsigned int fec_block_nos[],
                const unsigned int erased_blocks[],
                unsigned short nr_fec_blocks  /* how many blocks per stripe */);

void fec_license();

// ---------------------------------- C++ code ------------------------------------------------------------
#include <vector>
#include <array>

/**
 * Like fec_encode, but c++-style
 * @param fragmentSize size of each fragment in this block
 * @param primaryFragments list of pointers to memory for primary fragments
 * @param secondaryFragments list of pointers to memory for secondary fragments (fec fragments)
 * Using the data from @param primaryFragments constructs as many secondary fragments as @param secondaryFragments holds
 */
void fec_encode2(unsigned int fragmentSize,
                 const std::vector<const uint8_t *> &primaryFragments,
                 const std::vector<uint8_t *> &secondaryFragments);

/**
 * Like fec_decode, but c++-style & syntax that better fits a streaming usage.
 * @param fragmentSize size of each fragment in this block
 * @param primaryFragments list of pointers to memory for primary fragments. Must be same size as used for fec_encode()
 * @param indicesMissingPrimaryFragments list of the indices of missing primary fragments.
 * Example: if @param indicesMissingPrimaryFragments contains 2, the 3rd primary fragment is missing
 * @param secondaryFragmentsReceived list of pointers to memory for secondary fragments (fec fragments). Must not be same size as used for fec_encode(), only MUST contain "enough" secondary fragments
 * @param indicesOfSecondaryFragmentsReceived list of the indices of secondaryFragments that are used to reconstruct missing primary fragments.
 * Example: if @param indicesOfSecondaryFragmentsReceived contains {0,2}, the first secondary fragment has the index 0, and the second secondary fragment has the index 2
 * When this call returns, all missing primary fragments (gaps) have been filled / reconstructed
 */
void fec_decode2(unsigned int fragmentSize,
                 const std::vector<uint8_t *> &primaryFragments,
                 const std::vector<unsigned int> &indicesMissingPrimaryFragments,
                 const std::vector<uint8_t *> &secondaryFragmentsReceived,
                 const std::vector<unsigned int> &indicesOfSecondaryFragmentsReceived);

// these methods just wrap the methods above for commonly used data representations
template<class Container1, class Container2>
void fec_encode3(unsigned int fragmentSize, const std::vector<const Container1> &primaryFragments,
                 std::vector<Container2> &secondaryFragments);

template<class Container1, class Container2>
void fec_decode3(unsigned int fragmentSize,
                 std::vector<Container1> &primaryFragments,
                 const std::vector<unsigned int> &indicesMissingPrimaryFragments,
                 std::vector<Container2> &secondaryFragmentsReceived,
                 const std::vector<unsigned int> &indicesOfSecondaryFragmentsReceived);

// print the underlying optimization method
void print_optimization_method();

// Test the (optimized) galois field math
void test_gf();

// Test the fec encoding & reconstructing step
void test_fec();

#endif //FEC_BASE_H