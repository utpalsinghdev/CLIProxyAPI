package cxcompat

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const lockWait = 20 * time.Second

type lockOwner struct {
	PID int `json:"pid"`
}

func (s *Store) withAccountLock(ctx context.Context, email string, action func() error) error {
	ctx, cancel := context.WithTimeout(ctx, lockWait)
	defer cancel()
	path := accountPath(s.accountsDir(), email) + ".lock"
	for {
		if ctx.Err() != nil {
			return errors.New("account refresh is busy; try again shortly")
		}
		if err := os.Mkdir(path, 0o700); err == nil {
			if err := os.Chmod(path, 0o700); err != nil {
				_ = os.Remove(path)
				return errors.New("account lock is unavailable")
			}
			owner, marshalErr := json.Marshal(lockOwner{PID: os.Getpid()})
			if marshalErr != nil {
				_ = os.Remove(path)
				return errors.New("account lock is unavailable")
			}
			if err := os.WriteFile(filepath.Join(path, "owner.json"), owner, 0o600); err != nil {
				_ = os.RemoveAll(path)
				return errors.New("account lock is unavailable")
			}
			if ctx.Err() != nil {
				_ = os.RemoveAll(path)
				return errors.New("account refresh is busy; try again shortly")
			}
			err := action()
			_ = os.RemoveAll(path)
			return err
		} else if !errors.Is(err, os.ErrExist) {
			return errors.New("account lock is unavailable")
		}
		if err := reclaimDeadLock(path); err != nil {
			return err
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return errors.New("account refresh is busy; try again shortly")
		case <-timer.C:
		}
	}
}

func reclaimDeadLock(path string) error {
	ownerPath := filepath.Join(path, "owner.json")
	data, err := os.ReadFile(ownerPath)
	if err != nil {
		return nil
	}
	var owner lockOwner
	if json.Unmarshal(data, &owner) != nil || owner.PID <= 0 {
		return nil
	}
	if !processIsDead(owner.PID) {
		return nil
	}

	recovery := path + ".recovery"
	if err := os.Mkdir(recovery, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return errors.New("account lock recovery is unavailable")
	}
	defer func() { _ = os.RemoveAll(recovery) }()
	// Verify the same dead owner under the recovery gate before removing anything.
	current, err := os.ReadFile(ownerPath)
	if err != nil || string(current) != string(data) {
		return nil
	}
	var confirmed lockOwner
	if json.Unmarshal(current, &confirmed) != nil || confirmed.PID != owner.PID {
		return nil
	}
	if processIsDead(confirmed.PID) {
		_ = os.RemoveAll(path)
	}
	return nil
}

// Platforms without a non-destructive liveness probe retain the lock rather than guess.
func processIsDead(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	defer func() { _ = process.Release() }()
	err = process.Signal(syscall.Signal(0))
	return errors.Is(err, syscall.ESRCH) || errors.Is(err, os.ErrProcessDone)
}
