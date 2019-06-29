// +build !confonly

package dns

import (
	"reflect"
	"testing"
	"time"

	"v2ray.com/core/common/net"
)

func Test_dohDNSResult_getIPs(t *testing.T) {
	type fields struct {
		domain string
		A      *dohIPRecord
		AAAA   *dohIPRecord
	}
	type args struct {
		option IPOption
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []net.IP
	}{
		// TODO: Add test cases.
		{
			name: "full",
			fields: fields{
				domain: "v2ray.com",
				A: &dohIPRecord{
					ips:    []net.IP{net.ParseIP("123.123.123.123")},
					expire: time.Now().Add(time.Second * 30),
				},
				AAAA: &dohIPRecord{
					ips:    []net.IP{net.ParseIP("[2001::123]")},
					expire: time.Now().Add(time.Second * 30),
				},
			},
			args: args{IPOption{IPv4Enable: true, IPv6Enable: true}},
			want: []net.IP{net.ParseIP("[2001::123]"), net.ParseIP("123.123.123.123")},
		},
		{
			name: "expired",
			fields: fields{
				domain: "v2ray.com",
				A: &dohIPRecord{
					ips:    []net.IP{net.ParseIP("123.123.123.123")},
					expire: time.Now().Add(time.Second * 30),
				},
				AAAA: &dohIPRecord{
					ips:    []net.IP{net.ParseIP("[2001::123]")},
					expire: time.Now().Truncate(time.Second * 30),
				},
			},
			args: args{IPOption{IPv4Enable: true, IPv6Enable: true}},
			want: []net.IP{net.ParseIP("123.123.123.123")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &dohDNSResult{
				domain: tt.fields.domain,
				A:      tt.fields.A,
				AAAA:   tt.fields.AAAA,
			}
			if got := r.getIPs(tt.args.option); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("dohDNSResult.getIPs() = %v, want %v", got, tt.want)
			}
		})
	}
}
