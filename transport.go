package omemo

import "context"

// Transport is everything this library needs a concrete XMPP (or other)
// backend to provide network access for. It never sends or receives actual
// chat messages: an EncryptedMessage produced by Manager.EncryptMessage is
// the application's own responsibility to deliver via its normal
// message-sending path, and an incoming one is handed to
// Manager.DecryptMessage the same way. Transport exists only for the
// out-of-band bundle and device-list exchange (e.g. XMPP PEP) that OMEMO's
// own state machine initiates on its own schedule.
type Transport interface {
	FetchDeviceList(ctx context.Context, jid string) (DeviceList, error)
	PublishDeviceList(ctx context.Context, list DeviceList) error

	FetchBundle(ctx context.Context, dev Device) (Bundle, error)
	PublishBundle(ctx context.Context, bundle Bundle) error
}
