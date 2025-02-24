//go:build cloud_collector

package agent

import (
	_ "flashcat.cloud/categraf/inputs/aliyun"
	_ "flashcat.cloud/categraf/inputs/cms_aliyun"
	_ "flashcat.cloud/categraf/inputs/cms_tencent"
	_ "flashcat.cloud/categraf/inputs/cms_volcengine"
	_ "flashcat.cloud/categraf/inputs/tencent"
)
