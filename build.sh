#!/usr/bin/env ash

RELEASE=${1:-"true"}
VERBOSITY="error"

echo "Building COMMIT :: $CI_PROJECT_NAME:$CI_COMMIT_SHORT_SHA"
/kaniko/executor \
    --verbosity ${VERBOSITY} \
    --context $CI_PROJECT_DIR \
    --registry-mirror dockerhub.devops.telekom.de \
    --dockerfile $CI_PROJECT_DIR/Dockerfile \
    --destination "$CI_REGISTRY_IMAGE/$CI_PROJECT_NAME:$CI_COMMIT_SHORT_SHA" \
    --cache=true --cache-repo $CI_REGISTRY_IMAGE/$CI_PROJECT_NAME \
    --build-arg ARG_OPENSHIFT_CLIENT_URL=$OPENSHIFT_CLIENT_URL \
    --build-arg http_proxy=$http_proxy \
    --build-arg https_proxy=$https_proxy \
    --build-arg no_proxy=$no_proxy \
    --cleanup
if [ "$RELEASE" = "true" ]
    then
        echo "Building RELEASE :: $CI_PROJECT_NAME:[$CI_COMMIT_TAG, latest]"
        /kaniko/executor \
            --verbosity ${VERBOSITY} \
            --context $CI_PROJECT_DIR \
            --registry-mirror dockerhub.devops.telekom.de \
            --dockerfile $CI_PROJECT_DIR/Dockerfile \
            --destination "$CI_REGISTRY_IMAGE/$CI_PROJECT_NAME:$CI_COMMIT_TAG" \
            --cache=true --cache-repo $CI_REGISTRY_IMAGE/$CI_PROJECT_NAME \
            --build-arg ARG_OPENSHIFT_CLIENT_URL=$OPENSHIFT_CLIENT_URL \
            --build-arg http_proxy=$http_proxy \
            --build-arg https_proxy=$https_proxy \
            --build-arg no_proxy=$no_proxy \
            --cleanup
        /kaniko/executor \
            --verbosity ${VERBOSITY} \
            --context $CI_PROJECT_DIR \
            --registry-mirror dockerhub.devops.telekom.de \
            --dockerfile $CI_PROJECT_DIR/Dockerfile \
            --destination "$CI_REGISTRY_IMAGE/$CI_PROJECT_NAME:latest" \
            --cache=true --cache-repo $CI_REGISTRY_IMAGE/$CI_PROJECT_NAME \
            --build-arg ARG_OPENSHIFT_CLIENT_URL=$OPENSHIFT_CLIENT_URL \
            --build-arg http_proxy=$http_proxy \
            --build-arg https_proxy=$https_proxy \
            --build-arg no_proxy=$no_proxy \
            --cleanup
    else
        echo "Building non RELEASE :: $CI_PROJECT_NAME:$CI_COMMIT_REF_SLUG"
        /kaniko/executor \
            --verbosity ${VERBOSITY} \
            --context $CI_PROJECT_DIR \
            --registry-mirror dockerhub.devops.telekom.de \
            --dockerfile $CI_PROJECT_DIR/Dockerfile \
            --destination "$CI_REGISTRY_IMAGE/$CI_PROJECT_NAME:$CI_COMMIT_REF_SLUG" \
            --cache=true --cache-repo $CI_REGISTRY_IMAGE/$CI_PROJECT_NAME \
            --build-arg ARG_OPENSHIFT_CLIENT_URL=$OPENSHIFT_CLIENT_URL \
            --build-arg http_proxy=$http_proxy \
            --build-arg https_proxy=$https_proxy \
            --build-arg no_proxy=$no_proxy \
            --cleanup
fi
