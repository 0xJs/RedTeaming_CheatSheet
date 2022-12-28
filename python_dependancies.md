# Best way to handle python dependancies
- https://www.youtube.com/watch?v=ieyRV9zQd2U&t=2915s


## Pipx
#### Install pipx
```
python3 -m pip install pipx 
python3 -m pipx ensurepath
```

#### Install tools/packages with pipx
```
pipx install package
```

## Virtual env
#### Install
```
python3 -m pip install --user virtualenv
```

#### Create virtual env
```
mkdir my_awesome_project
cd my_awesome_project
python3 -m venv .my_awesome_project_venv
```

#### Use virtual env
```
source .my_awesome_project_venv/bin/activate
(.my_awesome_project_venv) # pip install requests
```
