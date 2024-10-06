
// IdaOgg: A mini Vorbis Ogg clip player for IDA
// By Sirmabus 2015
// Site: http://www.macromonkey.com
// License: 
#define WIN32_LEAN_AND_MEAN
#define WINVER       0x0601 // _WIN32_WINNT_WIN7
#define _WIN32_WINNT 0x0601
#include <Windows.h>
#include <exception>
#include <stdlib.h>
#include <mmsystem.h>

// Nix the many warning about int type conversions
#pragma warning(push)
#pragma warning(disable:4244)
#pragma warning(disable:4267)
#include <ida.hpp>
#include <kernwin.hpp>
#pragma warning(pop)

#include "stb_vorbis.h"
#include "IdaOgg.h"

// Required libs
#pragma comment(lib, "ida.lib")
#pragma comment(lib, "winmm.lib")

#undef MYCATCH
#define MYCATCH() catch (...) { msg("** Exception in ogg method: %s()! ***\n", __FUNCTION__); }

// Only 16bit samples are supported
const int BITS_PER_SAMPLE = 16;

#if 0
void trace(LPCTSTR pszFormat, ...)
{
    if (pszFormat)
    {
        va_list vl;
        char szBuffer[4096];
        va_start(vl, pszFormat);
        ::qvsnprintf(szBuffer, (sizeof(szBuffer) - 1), pszFormat, vl);
        szBuffer[sizeof(szBuffer) - 1] = 0;
        va_end(vl);

        OutputDebugString(szBuffer);
    }
}
#endif

#if 0
typedef double TIMESTAMP;  // Time in floating seconds
static TIMESTAMP GetTimeStamp()
{
    LARGE_INTEGER tLarge;
    QueryPerformanceCounter(&tLarge);

    static TIMESTAMP s_ClockFreq;
    if (s_ClockFreq == 0.0)
    {
        LARGE_INTEGER tLarge;
        QueryPerformanceFrequency(&tLarge);
        s_ClockFreq = (TIMESTAMP)tLarge.QuadPart;
    }

    return((TIMESTAMP)tLarge.QuadPart / s_ClockFreq);
}
#endif

// RIFF wave header
#pragma pack(push, 1)
struct WAVE_HEADER
{
    FOURCC	riffTag;
    DWORD   riffSize;
    //
    FOURCC	waveTag;
    FOURCC	fmtTag;
    int	    fmtSize;
    //
    WAVEFORMATEX wfm;
    //
    FOURCC	dataTag;
    int	    dataSize;
} static *gHeader = NULL;
#pragma pack(pop)

// Play sound from memory
void OggPlay::playFromMemory(const PVOID source, int length, BOOL async /*= FALSE*/)
{
    try
    {
        if (!gHeader)
        {
            int nChannels = 0, nSamplesPerSec = 0;
            short *rawPcm = NULL;
            //TIMESTAMP startTime = GetTimeStamp();
            int samples = stb_vorbis_decode_memory((const unsigned char *) source, length, &nChannels, &nSamplesPerSec, &rawPcm);
            //TIMESTAMP endTime = (GetTimeStamp() - startTime);
            //msg("Decode time: %f\n", endTime);

            if (samples > 0)
            {
                // Space for WAV header + data
                UINT sampleSize = (samples * sizeof(short));
                if (WAVE_HEADER *waveData = (WAVE_HEADER *)_aligned_malloc((sizeof(WAVE_HEADER) + sampleSize + 64), 16))
                {
                    // Fill header
                    waveData->riffTag  = FOURCC_RIFF;
                    waveData->riffSize = ((sizeof(WAVE_HEADER) + sampleSize) - 8);  // Total file size, not including the first 8 bytes
                    //
                    waveData->waveTag = mmioFOURCC('W', 'A', 'V', 'E');
                    waveData->fmtTag  = mmioFOURCC('f', 'm', 't', ' ');
                    waveData->fmtSize = sizeof(WAVEFORMATEX);
                    //
                    waveData->wfm.wFormatTag      = WAVE_FORMAT_PCM;
                    waveData->wfm.nChannels       = nChannels;
                    waveData->wfm.nSamplesPerSec  = nSamplesPerSec;
                    waveData->wfm.nAvgBytesPerSec = ((nSamplesPerSec  * sizeof(short)) * nChannels);
                    waveData->wfm.nBlockAlign     = ((nChannels * BITS_PER_SAMPLE) / 8);
                    waveData->wfm.wBitsPerSample  = BITS_PER_SAMPLE;
                    waveData->wfm.cbSize = 0;
                    //
                    waveData->dataTag = mmioFOURCC('d', 'a', 't', 'a');
                    waveData->dataSize = sampleSize;

                    // Copy just PCM data & free buffer
                    memcpy(&waveData[1], rawPcm, sampleSize);                    
                    stb_vorbis_free_buffer(rawPcm);
                    rawPcm = NULL;

                    // TODO: Not adding the useless "INFO LIST" chunk causes a problem?
                    // See: http://en.wikipedia.org/wiki/WAV                

                    // Play the decoded wave
                    ::PlaySound((LPCTSTR)waveData, NULL, (SND_MEMORY | ((async == TRUE) ? SND_ASYNC : 0)));
                    
                    /// Not async we can clean up now sound is done
                    if (!async)                                                          
                        endPlay();                    
                }                
            }
                    
            stb_vorbis_free_buffer(rawPcm);           
        }
        else
            msg(__FUNCTION__": An Ogg is already playing!\n");
    }   
    MYCATCH()
}

// Stop the Ogg if it's still playing and do necessary clean up
void OggPlay::endPlay()
{
    try
    {      
        // Stop the sound if it's playing
        ::PlaySound(NULL, NULL, SND_ASYNC);
       
        // While async mode
        if (gHeader)
        {          
            _aligned_free(gHeader);
            gHeader = NULL;
        }
            
        stb_vorbis_heap_destroy();                   
    }
    MYCATCH()
}
