#!/bin/sh

echo "Copying configs...."
cp -rf api-manager.xml wso2am-2.2.0/repository/conf/api-manager.xml
cp -rf carbon.xml wso2am-2.2.0/repository/conf/carbon.xml 
cp -rf log4j.properties wso2am-2.2.0/repository/conf/log4j.properties
cp -rf _TokenAPI_.xml  wso2am-2.2.0/repository/deployment/server/synapse-configs/default/api/_TokenAPI_.xml

echo "Copying configs ....... [DONE] "
