package pkiaas

import "fmt"

// Version field is a SemVer that should indicate the baked-in version
// of the broker
<<<<<<< HEAD
var Version = "0.4.3"
=======
var Version = "0.4.2"
>>>>>>> Added panic for invalid initialization

// Tag field denotes the specific build type for the broker. It may
// be replaced by compile-time variables if needed to provide the git
// commit information in the final binary. See `Static long version tags`
// in the `Building` section of `CONTRIBUTING.md` for more information on
// this variable.
var Tag = "alpha"

// FullVersionName is the user-visible aggregation of version and tag
// of this codebase
var FullVersionName = fmt.Sprintf("%s-%s", Version, Tag)
