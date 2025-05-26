#!/bin/bash

kubectl delete -f ../zookeeper-deployment.yaml --ignore-not-found=true
kubectl delete -f ../zookeeper-service.yaml --ignore-not-found=true

kubectl delete -f ../kafka-deployment.yaml --ignore-not-found=true
kubectl delete -f ../kafka-service.yaml --ignore-not-found=true

kubectl delete -f ../kafka-ui-deployment.yaml --ignore-not-found=true
kubectl delete -f ../kafka-ui-service.yaml --ignore-not-found=true

kubectl delete -f ../postgres-deployment.yaml --ignore-not-found=true
kubectl delete -f ../postgres-service.yaml --ignore-not-found=true
