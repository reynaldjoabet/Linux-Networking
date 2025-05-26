#!/bin/bash

kubectl delete -f ../kafka-ui-deployment.yaml --ignore-not-found=true
kubectl delete -f ../kafka-ui-service.yaml --ignore-not-found=true

kubectl apply -f ../kafka-ui-deployment.yaml
kubectl apply -f ../kafka-ui-service.yaml