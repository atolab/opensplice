/*
*                         OpenSplice DDS
*
 *   This software and documentation are Copyright 2006 to TO_YEAR PrismTech
 *   Limited, its affiliated companies and licensors. All rights reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
*
*/


/**
 * @file
 */

#ifndef ORG_OPENSPLICE_SUB_QOS_QOSCONVERTER_HPP_
#define ORG_OPENSPLICE_SUB_QOS_QOSCONVERTER_HPP_

#include <dds/core/types.hpp>
#include <dds/sub/qos/DataReaderQos.hpp>
#include <dds/sub/qos/SubscriberQos.hpp>
#include <org/opensplice/core/config.hpp>

namespace org
{
namespace opensplice
{
namespace sub
{
namespace qos
{
dds::sub::qos::DataReaderQos
OSPL_ISOCPP_IMPL_API convertQos(const DDS::DataReaderQos& from);

DDS::DataReaderQos
OSPL_ISOCPP_IMPL_API convertQos(const dds::sub::qos::DataReaderQos& from);

dds::sub::qos::SubscriberQos
OSPL_ISOCPP_IMPL_API convertQos(const DDS::SubscriberQos& from);

DDS::SubscriberQos
OSPL_ISOCPP_IMPL_API convertQos(const dds::sub::qos::SubscriberQos& from);
}
}
}
}

#endif /* ORG_OPENSPLICE_SUB_QOS_QOSCONVERTER_HPP_ */
