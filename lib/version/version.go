package version

const VERSION = "0.30.2"
const MinVer = 3

var MinVersions = []string{
	"0.26.0", // 0
	"0.27.0", // 1
	"0.28.0", // 2
	"0.29.0", // 3
	"0.30.0", // 4
}

func GetVersion(index int) string {
	if index < 0 || index >= len(MinVersions) {
		return GetLatest()
	}
	return MinVersions[index]
}

func GetMinVersion(SecureMode bool) string {
	if SecureMode {
		return GetVersion(MinVer)
	}
	return GetVersion(0)
}

func GetCount() int {
	return len(MinVersions)
}

func GetLatest() string {
	if len(MinVersions) == 0 {
		return ""
	}
	return MinVersions[len(MinVersions)-1]
}

func GetIndex(ver string) int {
	for i, v := range MinVersions {
		if v == ver {
			return i
		}
	}
	return -1
}

func GetLatestIndex() int {
	if GetCount() == 0 {
		return 0
	}
	return GetCount() - 1
}
