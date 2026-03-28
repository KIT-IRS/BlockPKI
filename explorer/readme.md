To run explorer you need to copy the respective crypto data from the generated instance:

cp -r ../test-network/organizations/ .

To achieve:

organizations/ordererOrganizations/
organizations/peerOrganizations/

Then:
docker-compose up -d

and login with:

exploreradmin
exploreradminpw

