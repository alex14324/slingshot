#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <GdiPlus.h> // Screenshot
#pragma comment(lib, "Gdiplus.lib") // Screenshot

class CHandleGuard
{
	HANDLE h_;
	CHandleGuard(CHandleGuard&);
	CHandleGuard& operator=(CHandleGuard&);
public:
	explicit CHandleGuard(HANDLE h = 0)
		:h_(h) {}
	~CHandleGuard(void)
	{
		if (h_)CloseHandle(h_);
	}
	HANDLE get() const { return h_; }
	HANDLE release()
	{
		HANDLE tmp = h_;
		h_ = 0;
		return tmp;
	}
	void reset(HANDLE h)
	{
		if (h_)CloseHandle(h_);
		h_ = h;
	}
};

class CDCGuard
{
	HDC h_;
	CDCGuard(const CDCGuard&);
	CDCGuard& operator=(CDCGuard&);
public:
	explicit CDCGuard(HDC h)
		:h_(h) {}
	~CDCGuard(void)
	{
		if (h_)DeleteDC(h_);
	}
	void reset(HDC h)
	{
		if (h_ == h)
			return;
		if (h_)DeleteDC(h_);
		h_ = h;
	}
	void release()
	{
		h_ = 0;
	}
	HDC get()
	{
		return h_;
	}
};
class CBitMapGuard
{
	HBITMAP h_;
	CBitMapGuard(const CBitMapGuard&);
	CBitMapGuard& operator=(CBitMapGuard&);
public:
	explicit CBitMapGuard(HBITMAP h)
		:h_(h) {}
	~CBitMapGuard(void)
	{
		if (h_)DeleteObject(h_);
	}
	void reset(HBITMAP h)
	{
		if (h_ == h)
			return;
		if (h_)DeleteObject(h_);
		h_ = h;
	}
	HBITMAP get()
	{
		return h_;
	}
};

int GetEncoderClsid(wchar_t *format, CLSID *pClsid)
{
	unsigned int num = 0, size = 0;
	Gdiplus::GetImageEncodersSize(&num, &size);

	if (size == 0) return -1;

	Gdiplus::ImageCodecInfo *pImageCodecInfo = (Gdiplus::ImageCodecInfo *)(malloc(size));
	if (pImageCodecInfo == NULL) return -1;

	Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);
	for (unsigned int j = 0; j < num; ++j)
	{
		if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0)
		{
			*pClsid = pImageCodecInfo[j].Clsid;
			free(pImageCodecInfo);
			return j;
		}
	}
	free(pImageCodecInfo);
	return 0;

}

BOOL CALLBACK MonitorEnumProc(
	HMONITOR hMonitor,  // handle to display monitor
	HDC hdcMonitor,     // handle to monitor DC
	LPRECT lprcMonitor, // monitor intersection rectangle
	LPARAM dwData       // data
);

typedef std::vector<std::pair<HDC, RECT>> HDCPoolType;

class CDisplayHandlesPool
{
private:
	HDCPoolType m_hdcPool;

	CDisplayHandlesPool(const CDisplayHandlesPool & other);
	CDisplayHandlesPool & operator = (CDisplayHandlesPool);
public:

	typedef HDCPoolType::iterator iterator;

	CDisplayHandlesPool()
	{
		CDCGuard captureGuard(0);
		HDC hDesktopDC = GetDC(NULL);
		CDCGuard desktopGuard(hDesktopDC);
		EnumDisplayMonitors(hDesktopDC, NULL, MonitorEnumProc, reinterpret_cast<LPARAM>(this));
	}
	~CDisplayHandlesPool()
	{
		for (HDCPoolType::iterator it = m_hdcPool.begin(); it != m_hdcPool.end(); ++it)
		{
			if (it->first)
				DeleteDC(it->first);
		}
	}

	void AddHdcToPool(CDCGuard & hdcGuard, RECT rect)
	{
		m_hdcPool.push_back(std::make_pair(hdcGuard.get(), rect));
		hdcGuard.release();
	}

	iterator begin()
	{
		return m_hdcPool.begin();
	}
	iterator end()
	{
		return m_hdcPool.end();
	}
};





void CreateBitmapFinal(std::vector<unsigned char> & data, CDCGuard &captureGuard, CBitMapGuard & bmpGuard, HGDIOBJ & originalBmp, int nScreenWidth, int nScreenHeight)
{
	// save data to buffer
	unsigned char charBitmapInfo[sizeof(BITMAPINFOHEADER) + 256 * sizeof(RGBQUAD)] = { 0 };
	LPBITMAPINFO lpbi = (LPBITMAPINFO)charBitmapInfo;
	lpbi->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	lpbi->bmiHeader.biHeight = nScreenHeight;
	lpbi->bmiHeader.biWidth = nScreenWidth;
	lpbi->bmiHeader.biPlanes = 1;
	lpbi->bmiHeader.biBitCount = 24;
	lpbi->bmiHeader.biCompression = BI_RGB;

	//lpbi->bmiHeader.biCompression = BI_PNG;
	SelectObject(captureGuard.get(), originalBmp);
	GetDIBits(captureGuard.get(), bmpGuard.get(), 0, nScreenHeight, NULL, lpbi, DIB_RGB_COLORS);

	DWORD ImageSize = lpbi->bmiHeader.biSizeImage;

	DWORD PalEntries = 3;
	if (lpbi->bmiHeader.biCompression != BI_BITFIELDS)
		PalEntries = (lpbi->bmiHeader.biBitCount <= 8) ? (int)(1 << lpbi->bmiHeader.biBitCount) : 0;
	if (lpbi->bmiHeader.biClrUsed)
		PalEntries = lpbi->bmiHeader.biClrUsed;

	data.resize(sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + PalEntries * sizeof(RGBQUAD) + ImageSize);

	DWORD imageOffset = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + PalEntries * sizeof(RGBQUAD);
	DWORD infoHeaderOffset = sizeof(BITMAPFILEHEADER);
	BITMAPFILEHEADER * pFileHeader = (BITMAPFILEHEADER *)&data[0];
	pFileHeader->bfType = 19778; // always the same, 'BM'
	pFileHeader->bfReserved1 = pFileHeader->bfReserved2 = 0;
	pFileHeader->bfOffBits = imageOffset;
	pFileHeader->bfSize = ImageSize;

	GetDIBits(captureGuard.get(), bmpGuard.get(), 0, nScreenHeight, &data[imageOffset], lpbi, DIB_RGB_COLORS);

	memcpy(&data[sizeof(BITMAPFILEHEADER)], &lpbi->bmiHeader, sizeof(BITMAPINFOHEADER));

}

void SpliceImages(CDisplayHandlesPool *pHdcPool, CDCGuard &captureGuard, CBitMapGuard &bmpGuard, HGDIOBJ &originalBmp, int *width, int *height)
{
	HDC hDesktopDC = GetDC(NULL);
	CDCGuard desktopGuard(hDesktopDC);

	unsigned int nScreenWidth = GetSystemMetrics(SM_CXVIRTUALSCREEN);
	unsigned int nScreenHeight = GetSystemMetrics(SM_CYVIRTUALSCREEN);
	*width = nScreenWidth;
	*height = nScreenHeight;

	HDC hCaptureDC = CreateCompatibleDC(desktopGuard.get());
	captureGuard.reset(hCaptureDC);

	HBITMAP hCaptureBmp = CreateCompatibleBitmap(desktopGuard.get(), nScreenWidth, nScreenHeight);
	bmpGuard.reset(hCaptureBmp);
	originalBmp = SelectObject(hCaptureDC, hCaptureBmp);

	// Calculating coordinates shift if any monitor has negative coordinates
	long shiftLeft = 0;
	long shiftTop = 0;
	for (HDCPoolType::iterator it = pHdcPool->begin(); it != pHdcPool->end(); ++it)
	{
		if (it->second.left < shiftLeft)
			shiftLeft = it->second.left;
		if (it->second.top < shiftTop)
			shiftTop = it->second.top;
	}

	for (HDCPoolType::iterator it = pHdcPool->begin(); it != pHdcPool->end(); ++it)
		BitBlt(hCaptureDC, it->second.left - shiftLeft, it->second.top - shiftTop, it->second.right - it->second.left, it->second.bottom - it->second.top, it->first, 0, 0, SRCCOPY);
}

void CaptureDesktop(CDCGuard &desktopGuard, CDCGuard &captureGuard, CBitMapGuard & bmpGuard, HGDIOBJ & originalBmp, int * width, int * height, int left, int top)
{
	unsigned int nScreenWidth = GetDeviceCaps(desktopGuard.get(), HORZRES);
	unsigned int nScreenHeight = GetDeviceCaps(desktopGuard.get(), VERTRES);
	*height = nScreenHeight;
	*width = nScreenWidth;

	// Creating a memory device context (DC) compatible with the specified device
	HDC hCaptureDC = CreateCompatibleDC(desktopGuard.get());
	captureGuard.reset(hCaptureDC);

	// Creating a bitmap compatible with the device that is associated with the specified DC
	HBITMAP hCaptureBmp = CreateCompatibleBitmap(desktopGuard.get(), nScreenWidth, nScreenHeight);
	bmpGuard.reset(hCaptureBmp);

	// Selecting an object into the specified DC 
	originalBmp = SelectObject(hCaptureDC, hCaptureBmp);

	// Blitting the contents of the Desktop DC into the created compatible DC
	BitBlt(hCaptureDC, 0, 0, nScreenWidth, nScreenHeight, desktopGuard.get(), left, top, SRCCOPY | CAPTUREBLT);
}

BOOL CALLBACK MonitorEnumProc(
	HMONITOR hMonitor,  // handle to display monitor
	HDC hdcMonitor,        // handle to monitor DC
	LPRECT lprcMonitor,   // monitor intersection rectangle
	LPARAM dwData         // data
)
{
	CBitMapGuard bmpGuard(0);
	HGDIOBJ originalBmp = NULL;
	int height = 0;
	int width = 0;
	CDCGuard desktopGuard(hdcMonitor);
	CDCGuard captureGuard(0);
	CaptureDesktop(desktopGuard, captureGuard, bmpGuard, originalBmp, &width, &height, lprcMonitor->left, lprcMonitor->top);

	RECT rect = *lprcMonitor;
	CDisplayHandlesPool * hdcPool = reinterpret_cast<CDisplayHandlesPool *>(dwData);
	hdcPool->AddHdcToPool(captureGuard, rect);
	return true;
}

void CaptureScreen(std::vector<unsigned char>& dataScreen)
{
	CDCGuard captureGuard(0);
	CBitMapGuard bmpGuard(0);
	HGDIOBJ originalBmp = NULL;
	int height = 0;
	int width = 0;

	CDisplayHandlesPool displayHandles;
	SpliceImages(&displayHandles, captureGuard, bmpGuard, originalBmp, &width, &height);

	CreateBitmapFinal(dataScreen, captureGuard, bmpGuard, originalBmp, width, height);
}