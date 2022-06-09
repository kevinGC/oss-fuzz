// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package fuzzing

import (
	"bytes"
	"context"
	"flag"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/state"
)

func FuzzStateLoad(data []byte) int {
	const filename = "data"

	isChild := flag.Bool("child", false, "whether this process is the test child process")
	flag.Parse()

	if *isChild {
		dataFile, err := os.Open(filename)
		if err != nil {
			log.Fatal(err)
		}
		defer dataFile.Close()

		dataBytes, err := io.ReadAll(dataFile)
		if err != nil {
			log.Fatal(err)
		}

		ctx := context.Background()
		var toLoad *buffer.View
		_, _ = state.Load(ctx, bytes.NewReader(dataBytes), toLoad)
		return 1
	}

	dataFile, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(filename)

	if _, err := dataFile.Write(data); err != nil {
		log.Fatal(err)
	}

	cmd := exec.Command("/proc/self/exe", "-child")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}

	stderrOutput, err := io.ReadAll(stderr)
	if err != nil {
		log.Fatal(err)
	}

	if err := cmd.Wait(); err != nil {
		// It is intended behavior to panic if the input causes an OOM.
		if !strings.Contains(string(stderrOutput), "runtime: out of memory: cannot allocate") {
			log.Fatal(err)
		}
	}

	return 1
}
