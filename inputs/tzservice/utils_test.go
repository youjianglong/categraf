package tzservice

import (
	"reflect"
	"runtime"
	"testing"
)

func TestPathGet(t *testing.T) {
	var val interface{}
	var expected interface{}
	// Testing when key is empty
	val = "test"
	key := ""
	expected = "test"
	result := PathGet(val, key)
	if result != expected {
		t.Errorf("Expected %v, but got %v", expected, result)
	}

	// Testing when val is a map
	val = map[string]interface{}{
		"foo": "bar",
	}
	key = "foo"
	expected = "bar"
	result = PathGet(val, key)
	if result != expected {
		t.Errorf("Expected %v, but got %v", expected, result)
	}

	// Testing when val is a slice
	val = []interface{}{"apple", "banana", "cherry"}
	key = "1"
	expected = "banana"
	result = PathGet(val, key)
	if result != expected {
		t.Errorf("Expected %v, but got %v", expected, result)
	}

	// Testing when val is a slice
	val = []interface{}{
		map[string]interface{}{
			"name": "Alice",
			"age":  25,
		},
		map[string]interface{}{
			"name": "Bob",
			"age":  30,
		},
	}
	key = "0.name"
	expected = "Alice"
	result = PathGet(val, key)
	if result != expected {
		t.Errorf("Expected %v, but got %v", expected, result)
	}
	key = "1.name"
	expected = "Bob"
	result = PathGet(val, key)
	if result != expected {
		t.Errorf("Expected %v, but got %v", expected, result)
	}

	// Testing when key contains "*"
	val = []interface{}{
		map[string]interface{}{
			"name": "Alice",
			"age":  25,
		},
		map[string]interface{}{
			"name": "Bob",
			"age":  30,
		},
	}
	key = "*.name"
	expected = []interface{}{"Alice", "Bob"}
	result = PathGet(val, key)
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Expected %v, but got %v", expected, result)
	}
}

func TestParseCmd(t *testing.T) {
	// Test shell command
	t.Run("ShellCommand_WindowsOS", func(t *testing.T) {
		cmd := "echo hello"
		var expectedName string
		var expectedArgs []string
		if runtime.GOOS == "windows" {
			expectedName = "cmd"
			expectedArgs = []string{"/C", "echo hello"}
		} else {
			expectedName = "sh"
			expectedArgs = []string{"-c", "echo hello"}
		}

		name, args := ParseCmd(cmd, true)
		if name != expectedName {
			t.Errorf("Expected name to be %s, but got %s", expectedName, name)
		}
		if !reflect.DeepEqual(args, expectedArgs) {
			t.Errorf("Expected args to be %v, but got %v", expectedArgs, args)
		}
	})

	// Test command with multiple arguments
	t.Run("CommandWithMultipleArguments", func(t *testing.T) {
		cmd := "echo hello world"
		expectedName := "echo"
		expectedArgs := []string{"hello", "world"}

		name, args := ParseCmd(cmd, false)
		if name != expectedName {
			t.Errorf("Expected name to be %s, but got %s", expectedName, name)
		}
		if !reflect.DeepEqual(args, expectedArgs) {
			t.Errorf("Expected args to be %v, but got %v", expectedArgs, args)
		}
	})

	// Test command with escape characters
	t.Run("CommandWithEscapeCharacters", func(t *testing.T) {
		cmd := `echo "Hello, World!" "I'm a string" "\r\n\t"`
		expectedName := "echo"
		expectedArgs := []string{"Hello, World!", "I'm a string", "\r\n\t"}

		name, args := ParseCmd(cmd, false)
		if name != expectedName {
			t.Errorf("Expected name to be %s, but got %s", expectedName, name)
		}
		if !reflect.DeepEqual(args, expectedArgs) {
			t.Errorf("Expected args to be %v, but got %v", expectedArgs, args)
		}
	})
}
