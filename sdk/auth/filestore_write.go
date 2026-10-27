package auth

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	log "github.com/sirupsen/logrus"
)

// saveAuthMetadata replaces credentials only after the new contents reach disk.
// Truncating the live file can leave an empty credential after a crash or reboot.
func saveAuthMetadata(path string, raw []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".auth-*")
	if err != nil {
		return fmt.Errorf("create temporary credential: %w", err)
	}
	tmp := file.Name()
	defer func() {
		if errRemove := os.Remove(tmp); errRemove != nil && !os.IsNotExist(errRemove) {
			log.Errorf("auth filestore: remove temporary credential failed: %v", errRemove)
		}
	}()
	if _, errWrite := file.Write(raw); errWrite != nil {
		if errClose := file.Close(); errClose != nil {
			log.Errorf("auth filestore: close temporary credential failed: %v", errClose)
		}
		return fmt.Errorf("write temporary credential: %w", errWrite)
	}
	if errSync := file.Sync(); errSync != nil {
		if errClose := file.Close(); errClose != nil {
			log.Errorf("auth filestore: close temporary credential failed: %v", errClose)
		}
		return fmt.Errorf("sync temporary credential: %w", errSync)
	}
	if errClose := file.Close(); errClose != nil {
		return fmt.Errorf("close temporary credential: %w", errClose)
	}
	if errRename := os.Rename(tmp, path); errRename != nil {
		return fmt.Errorf("replace credential: %w", errRename)
	}
	// Windows does not support syncing a directory through os.File.Sync.
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open credential directory: %w", err)
	}
	defer func() {
		if errClose := directory.Close(); errClose != nil {
			log.Errorf("auth filestore: close credential directory failed: %v", errClose)
		}
	}()
	if errSync := directory.Sync(); errSync != nil {
		return fmt.Errorf("sync credential directory: %w", errSync)
	}
	return nil
}
