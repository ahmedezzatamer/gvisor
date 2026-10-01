// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package devpts

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

// traceTTYOutput reports, at the sentry/tty_output point, the bytes the holder
// of terminal tty's master end just read. The bytes are the copy taken out of
// the output queue itself, never read back from the reader's memory, so the
// reader cannot change what is reported.
func traceTTYOutput(ctx context.Context, tty uint32, data []byte) {
	info := &pb.TtyOutput{
		TtyIndex: tty,
		Data:     data,
	}
	fields := seccheck.Global.GetFieldSet(seccheck.PointTTYOutput)
	if t := kernel.TaskFromContext(ctx); t != nil && !fields.Context.Empty() {
		info.ContextData = &pb.ContextData{}
		kernel.LoadSeccheckData(t, fields.Context, info.ContextData)
	}
	if err := seccheck.Global.SentToSinks(func(c seccheck.Sink) error {
		return c.TTYOutput(ctx, fields, info)
	}); err != nil {
		log.Debugf("sentry/tty_output was not delivered to every sink: %v", err)
	}
}
