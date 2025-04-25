import argparse
import os
import json
import inspect
import importlib
from framework.logging.log_config import setup_logger
from framework.logging.log import INFO,DEBUG,ERROR,RESULT,WARN
from framework.logging.error import ExpError
test_results={}





def run_test(test_func,fw_check=True,args=None):
    file_name,class_name,test_func = test_func.rsplit(".",2)
    oem_config = "oem_config.json"
    if os.path.isfile(oem_config):
        with open(oem_config, 'r') as file:
            oem_config = json.load(file)
        DEBUG(f"Loaded configuration from {oem_config}")
    else:
        ERROR(f"Configuration file {oem_config} not found.")
        test_results[test_func] = 'fail'
    config_file="tests/oem_tests/config.json"
    if os.path.isfile(config_file):
        with open(config_file, 'r') as file:
            config = json.load(file)
        DEBUG(f"Loaded configuration from {config_file}")
    else:
        ERROR(f"Configuration file {config_file} not found.")
        test_results[test_func] = 'fail'
        return
    module_name = "tests.oem_tests." + file_name
    INFO(module_name)
    try:
        module = importlib.import_module(module_name)
    except ImportError as e:
        ERROR(f"Error importing module {module_name}: {e}")
        test_results[test_func] = 'fail'
        return
    cls = None
    for name, obj in inspect.getmembers(module):
        DEBUG(f"Name: {name}, Obj: {obj}")
        if inspect.isclass(obj) and name == class_name:
            cls = obj
            break
    if cls is None:
        ERROR(f"Class not found in module {module_name}")
        test_results[test_func] = 'fail'
        return
    
    test_args=config.get(test_func,{})
    kwargs = {
        "oem_config" : oem_config,
        "test_args" : test_args,
        "fw_check" : fw_check,
        "tc_filter" : args.tc_filter
    }
    try:
        instance = cls(**kwargs)
    except (Exception,ExpError)  as e:
        ERROR(f"Error creating instance of class {cls.__name__} : {e}")
        test_results[test_func] = 'fail'
        return
    if not args.skip_setup:
        if hasattr(instance, 'setup'):
            
            setup_method = getattr(instance, 'setup')
            try:
                setup_method()
            except (Exception,ExpError)  as e:
                ERROR(f"Error running setup method in {cls.__name__}: {e}")
                test_results[module_name+f".{cls.__name__}"] = 'CLASS setup fail'
                test_results[test_func] = 'fail'
                # if hasattr(instance, 'teardown'):
                #     teardown_method = getattr(instance, 'teardown')
                #     try:
                #         teardown_method()
                #     except (Exception,ExpError)  as e:
                #         ERROR(f"Error running teardown method in {cls.__name__}: {e}")
                #         # test_results[test_func] = 'fail'
                #         return
                return

    if hasattr(instance, test_func):
        method = getattr(instance, test_func)
        try:
            instance.test_args=config.get(test_func,{})
            method()
            INFO(f"Ran {test_func} in {cls.__name__}")
            test_results[test_func] = 'pass'
        except (Exception,ExpError)  as e:
            ERROR(f"Error running {test_func} in {cls.__name__}: {e}")
            try:
                # instance.setup_obj.get_entity_manager().test_teardown()
                INFO("teardown on fail")
            except Exception as e:
                ERROR(f"Failed to teardown entities: {e}")
            test_results[test_func] = 'fail'
    else:
        INFO(f"Function {test_func} not found in class {cls.__name__}.")
    if not args.skip_teardown:
        # Run teardown method if it exists
        if hasattr(instance, 'teardown'):
            teardown_method = getattr(instance, 'teardown')
            try:
                teardown_method()
            except (Exception,ExpError)  as e:
                ERROR(f"Error running teardown method in {cls.__name__}: {e}")
                # test_results[test_func] = 'fail'
                return
    
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test Runner")
    # group = parser.add_mutually_exclusive_group(required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("--debug", action="store_true", help="Enable debug mode"
                        ,default=False)
    parser.add_argument("--vfdriver", action="store_true", 
                        help="Install Guest VF driver",default=False)   
    parser.add_argument("--skip_fw_check", action="store_false", 
                        help="Skip firmware and driver version check",
                        default=False)
    parser.add_argument("--skip_setup",action="store_true",
                        help="skip setup creation",default=False)
    parser.add_argument("--tc_filter",action="store_true",
                        help="Check tc filters",default=False)
    parser.add_argument("--skip_teardown",action="store_true",
                        help="skip setup deletion",default=False)
    # group.add_argument("--test_func", type=str, 
    #                     help="Name of the test directory to run from the \
    #                     JSON file")
    parser.add_argument("--scaleout", action="store_true",
                        help="Run scaleout tests",default=False)
    group.add_argument("--intra", action="store_true",
                       help="Run intra-node tests")
    group.add_argument("--inter", action="store_true",
                          help="Run inter-node tests")
    group.add_argument("--run_all", action="store_true", help="Run all tests")
    intra = "test_intra.IntraNodeTest.test_intra_node"
    inter = "test_inter.InterNodeTest.test_inter_node"
    test = None
    args = parser.parse_args()
    if args.intra:
        test = intra
    elif args.inter:
        test = inter
    else:
        raise ValueError("Please provide a test to run")
    if args.scaleout:
        test = test + "_scaleout"
    if args.debug:
        setup_logger(True)
    run_test(test,(not args.skip_fw_check),args)
    
    # if args.intra:
    #     run_test(intra,(not args.skip_fw_check),args)
    # elif args.inter:
    #     run_test(inter,(not args.skip_fw_check),args)