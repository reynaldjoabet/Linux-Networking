#!/bin/bash

kubectl delete -f ../zookeeper-deployment.yaml --ignore-not-found=true
kubectl delete -f ../zookeeper-service.yaml --ignore-not-found=true

kubectl apply -f ../zookeeper-deployment.yaml
kubectl apply -f ../zookeeper-service.yaml