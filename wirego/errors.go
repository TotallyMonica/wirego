package wirego

import "fmt"

type DependencyError struct {
	File string
}

func (e DependencyError) Error() string {
	return fmt.Sprintf("dependency %s not found", e.File)
}
